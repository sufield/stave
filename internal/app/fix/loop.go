package fix

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	appverify "github.com/sufield/stave/internal/app/verify"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// LoopRequest defines the inputs for the fix-loop workflow.
type LoopRequest struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	OutDir       string
	MaxUnsafe    time.Duration
	AllowUnknown bool
	Stdout       io.Writer
	Stderr       io.Writer
}

// LoopDeps holds the injectable dependencies for the fix-loop workflow.
type LoopDeps struct {
	ObservationRepoFactory func() (contracts.ObservationRepository, error)
	ControlRepo            contracts.ControlRepository

	// Remediator controls user interaction during the loop.
	// When nil, NopRemediator is used (auto-approve, discard progress).
	Remediator Remediator
}

// evaluationState holds the result and snapshot count from one evaluation run.
type evaluationState struct {
	Result    *evaluation.Result
	Snapshots int
}

// Loop executes the apply-before, apply-after, and verify sequence.
func (s *Service) Loop(ctx context.Context, req LoopRequest, deps LoopDeps, am *ArtifactWriter, eb *EnvelopeBuilder) error {
	rem := deps.Remediator
	if rem == nil {
		rem = NopRemediator{}
	}

	// 1. Validate directories
	if err := ValidateLoopDirs(req); err != nil {
		return err
	}

	// 2. Load controls once for both runs
	rem.LogProgress("loading controls from " + req.ControlsDir)
	controls, err := loadControls(ctx, deps, req.ControlsDir)
	if err != nil {
		return err
	}

	// 3. Evaluate "before" state
	rem.LogProgress("evaluating before state from " + req.BeforeDir)
	before, err := s.evaluateState(ctx, deps, req, controls, req.BeforeDir, "before")
	if err != nil {
		return err
	}

	// 4. Evaluate "after" state
	rem.LogProgress("evaluating after state from " + req.AfterDir)
	after, err := s.evaluateState(ctx, deps, req, controls, req.AfterDir, "after")
	if err != nil {
		return err
	}

	// 5. Verify (compare before/after)
	cmp, err := appverify.Compare(appverify.CompareRequest{
		BeforeFindings:  before.Result.Findings,
		AfterFindings:   after.Result.Findings,
		BeforeSnapshots: before.Snapshots,
		AfterSnapshots:  after.Snapshots,
		MaxUnsafe:       req.MaxUnsafe,
		Now:             s.Clock.Now().UTC(),
		Sanitizer:       s.Sanitizer,
	})
	if err != nil {
		return err
	}
	verification := cmp.Verification

	// 6. Build envelopes
	beforeEnv, afterEnv := eb.BuildEvaluation(*before.Result), eb.BuildEvaluation(*after.Result)
	if err = safetyenvelope.ValidateEvaluation(beforeEnv); err != nil {
		return fmt.Errorf("before envelope invalid: %w", err)
	}
	if err = safetyenvelope.ValidateEvaluation(afterEnv); err != nil {
		return fmt.Errorf("after envelope invalid: %w", err)
	}

	// 7. Persist artifacts
	artifacts, err := am.PersistVerification(beforeEnv, afterEnv, verification)
	if err != nil {
		return err
	}

	// 8. Build and emit report
	report := BuildReport(req, s.Clock, verification, artifacts)
	return am.PersistReport(&report)
}

// ValidateLoopDirs checks that all required directories exist.
func ValidateLoopDirs(req LoopRequest) error {
	for _, dir := range []struct{ flag, path string }{
		{"--before", req.BeforeDir},
		{"--after", req.AfterDir},
		{"--controls", req.ControlsDir},
	} {
		info, err := os.Stat(dir.path)
		if err != nil {
			return fmt.Errorf("%s: %w", dir.flag, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s: %s is not a directory", dir.flag, dir.path)
		}
	}
	return nil
}

func loadControls(ctx context.Context, deps LoopDeps, dir string) ([]policy.ControlDefinition, error) {
	controls, err := deps.ControlRepo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load controls: %w", err)
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls in %s", appeval.ErrNoControls, dir)
	}
	return controls, nil
}

func (s *Service) evaluateState(
	ctx context.Context,
	deps LoopDeps,
	req LoopRequest,
	controls []policy.ControlDefinition,
	dir string,
	label string,
) (evaluationState, error) {
	loader, err := deps.ObservationRepoFactory()
	if err != nil {
		return evaluationState{}, fmt.Errorf("%s evaluation: create observation loader: %w", label, err)
	}
	result, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           ctx,
		ObservationsDir:   dir,
		Controls:          controls,
		MaxUnsafe:         req.MaxUnsafe,
		Clock:             s.Clock,
		AllowUnknownType:  req.AllowUnknown,
		StaveVersion:      version.String,
		ObservationLoader: loader,
		CELEvaluator:      s.CELEvaluator,
	})
	if err != nil {
		return evaluationState{}, fmt.Errorf("%s evaluation: %w", label, err)
	}
	return evaluationState{Result: result, Snapshots: snaps}, nil
}

// BuildReport creates a LoopReport from the verification results.
func BuildReport(req LoopRequest, clock interface{ Now() time.Time }, v safetyenvelope.Verification, artifacts LoopArtifacts) LoopReport {
	pass := v.Summary.Remaining == 0 && v.Summary.Introduced == 0
	reason := "all previously violating resources are now resolved"
	if !pass {
		reason = fmt.Sprintf("remaining=%d introduced=%d", v.Summary.Remaining, v.Summary.Introduced)
	}
	return LoopReport{
		SchemaVersion: kernel.SchemaFixLoop,
		Kind:          kernel.KindRemediationReport,
		CheckedAt:     v.Run.Now,
		Pass:          pass,
		Reason:        reason,
		MaxUnsafe:     req.MaxUnsafe.String(),
		Before:        ObservationSummary{Directory: req.BeforeDir, Snapshots: v.Run.BeforeSnapshots, Violations: v.Summary.BeforeViolations},
		After:         ObservationSummary{Directory: req.AfterDir, Snapshots: v.Run.AfterSnapshots, Violations: v.Summary.AfterViolations},
		Verification:  v.Summary,
		Artifacts:     artifacts,
	}
}

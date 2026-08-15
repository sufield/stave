package fix

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	appattest "github.com/sufield/stave/internal/app/attestation"
	"github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/version"
)

// LoopRequest defines the inputs for the fix-loop workflow.
type LoopRequest struct {
	BeforeDir         string
	AfterDir          string
	ControlsDir       string
	OutDir            string
	MaxUnsafeDuration time.Duration
	Stdout            io.Writer
	Stderr            io.Writer
}

// LoopDeps holds the injectable dependencies for the fix-loop workflow.
type LoopDeps struct {
	ObservationRepo contracts.ObservationRepository
	ControlRepo     contracts.ControlRepository
}

// evaluationState holds the result and snapshot count from one evaluation run.
type evaluationState struct {
	Result    *evaluation.ComplianceReport
	Snapshots int
}

// EvaluationParams bundles the data arguments for evaluateState,
// preventing accidental swaps of the two string parameters (Dir, Label).
type EvaluationParams struct {
	Deps     LoopDeps
	Req      LoopRequest
	Controls []policy.ControlDefinition
	Dir      string
	Label    string
}

// Loop executes the apply-before, apply-after, and verify sequence.
func (s *Service) Loop(ctx context.Context, req LoopRequest, deps LoopDeps, am *ArtifactWriter, eb *EnvelopeBuilder) error {
	if s == nil {
		return fmt.Errorf("fix: service is nil")
	}
	// 1. Validate directories
	if err := ValidateLoopDirs(req); err != nil {
		return err
	}

	// 2. Load controls once for both runs
	slog.Debug("loading controls", "dir", req.ControlsDir)
	controls, err := loadControls(ctx, deps, req.ControlsDir)
	if err != nil {
		return err
	}

	// 3. Evaluate "before" state
	slog.Debug("evaluating before state", "dir", req.BeforeDir)
	before, err := s.evaluateState(ctx, EvaluationParams{
		Deps: deps, Req: req, Controls: controls, Dir: req.BeforeDir, Label: "before",
	})
	if err != nil {
		return err
	}

	// 4. Evaluate "after" state
	slog.Debug("evaluating after state", "dir", req.AfterDir)
	after, err := s.evaluateState(ctx, EvaluationParams{
		Deps: deps, Req: req, Controls: controls, Dir: req.AfterDir, Label: "after",
	})
	if err != nil {
		return err
	}

	// 5. Verify (compare before/after)
	cmp, err := appattest.Compare(appattest.CompareRequest{
		BaselineFindings:  before.Result.Findings,
		TargetFindings:    after.Result.Findings,
		BaselineSnapshots: before.Snapshots,
		TargetSnapshots:   after.Snapshots,
		SLAThreshold:      req.MaxUnsafeDuration,
		EvalTime:          s.Clock.Now().UTC(),
		Sanitizer:         s.Sanitizer,
	})
	if err != nil {
		return fmt.Errorf("compare: %w", err)
	}
	verification := cmp.Attestation

	// 6. Build envelopes
	beforeEnv, err := eb.BuildEvaluation(before.Result)
	if err != nil {
		return fmt.Errorf("build before evaluation: %w", err)
	}
	afterEnv, err := eb.BuildEvaluation(after.Result)
	if err != nil {
		return fmt.Errorf("build after evaluation: %w", err)
	}
	if err = contractvalidator.ValidateAssessment(beforeEnv); err != nil {
		return fmt.Errorf("before envelope invalid: %w", err)
	}
	if err = contractvalidator.ValidateAssessment(afterEnv); err != nil {
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
// ValidateLoopDirs checks that required directories exist and are accessible.
// The optional statFn parameter allows testing without a real filesystem.
func ValidateLoopDirs(req LoopRequest, statFn ...func(string) (os.FileInfo, error)) error {
	stat := os.Stat
	if len(statFn) > 0 && statFn[0] != nil {
		stat = statFn[0]
	}
	for _, dir := range []struct{ flag, path string }{
		{"--before", req.BeforeDir},
		{"--after", req.AfterDir},
		{"--controls", req.ControlsDir},
	} {
		info, err := stat(dir.path)
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
	params EvaluationParams,
) (evaluationState, error) {
	result, snaps, err := appeval.RunDirectoryEvaluation(ctx, appeval.DirectoryEvaluationRequest{
		ObservationsDir:   params.Dir,
		Controls:          params.Controls,
		MaxUnsafeDuration: params.Req.MaxUnsafeDuration,
		Clock:             s.Clock,
		StaveVersion:      version.String,
		ObservationLoader: params.Deps.ObservationRepo,
		CELEvaluator:      s.CELEvaluator,
	})
	if err != nil {
		return evaluationState{}, fmt.Errorf("%s evaluation: %w", params.Label, err)
	}
	return evaluationState{Result: result, Snapshots: snaps}, nil
}

// BuildReport creates a LoopReport from the verification results.
func BuildReport(req LoopRequest, _ interface{ Now() time.Time }, v *report.Attestation, artifacts LoopArtifacts) LoopReport {
	pass := v.Summary.Open == 0 && v.Summary.Regressions == 0
	reason := "all previously violating resources are now resolved"
	if !pass {
		reason = fmt.Sprintf("remaining=%d introduced=%d", v.Summary.Open, v.Summary.Regressions)
	}
	return LoopReport{
		SchemaVersion:     kernel.SchemaFixLoop,
		Kind:              kernel.KindRemediationReport,
		CheckedAt:         v.Run.EvalTime,
		Passed:            pass,
		Reason:            reason,
		MaxUnsafeDuration: req.MaxUnsafeDuration.String(),
		Before:            ObservationSummary{Directory: req.BeforeDir, Snapshots: v.Run.BeforeSnapshots, Violations: v.Summary.PreviousViolations},
		After:             ObservationSummary{Directory: req.AfterDir, Snapshots: v.Run.AfterSnapshots, Violations: v.Summary.CurrentViolations},
		Verification:      v.Summary,
		Artifacts:         artifacts,
	}
}

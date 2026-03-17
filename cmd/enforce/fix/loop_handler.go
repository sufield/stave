package fix

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appeval "github.com/sufield/stave/internal/app/eval"
	appverify "github.com/sufield/stave/internal/app/verify"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/version"
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

// --- Data Models ---

type evaluationState struct {
	Result    *evaluation.Result
	Snapshots int
}

// LoopReport is the structured output of a fix-loop run.
type LoopReport struct {
	SchemaVersion kernel.Schema                      `json:"schema_version"`
	Kind          kernel.OutputKind                  `json:"kind"`
	CheckedAt     time.Time                          `json:"checked_at"`
	Pass          bool                               `json:"pass"`
	Reason        string                             `json:"reason"`
	MaxUnsafe     string                             `json:"max_unsafe"`
	Before        observationSummary                 `json:"before"`
	After         observationSummary                 `json:"after"`
	Verification  safetyenvelope.VerificationSummary `json:"verification"`
	Artifacts     LoopArtifacts                      `json:"artifacts,omitzero"`
}

type observationSummary struct {
	Directory  string `json:"directory"`
	Snapshots  int    `json:"snapshots"`
	Violations int    `json:"violations"`
}

// --- Orchestration ---

// Loop executes the apply-before, apply-after, and verify sequence.
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
	// 1. Validate directories
	if err := validateLoopDirs(req); err != nil {
		return err
	}

	// 2. Load controls once for both runs
	controls, err := r.loadControls(ctx, req.ControlsDir)
	if err != nil {
		return err
	}

	// 3. Evaluate "before" state
	before, err := r.evaluateState(ctx, req, controls, req.BeforeDir, "before")
	if err != nil {
		return err
	}

	// 4. Evaluate "after" state
	after, err := r.evaluateState(ctx, req, controls, req.AfterDir, "after")
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
		Now:             r.Clock.Now().UTC(),
		Sanitizer:       r.Sanitizer,
	})
	if err != nil {
		return err
	}
	verification := cmp.Verification

	// 6. Build envelopes
	eb := NewEnvelopeBuilder(r.Sanitizer)
	beforeEnv, afterEnv := eb.BuildEvaluation(*before.Result), eb.BuildEvaluation(*after.Result)
	if err = safetyenvelope.ValidateEvaluation(beforeEnv); err != nil {
		return fmt.Errorf("before envelope invalid: %w", err)
	}
	if err = safetyenvelope.ValidateEvaluation(afterEnv); err != nil {
		return fmt.Errorf("after envelope invalid: %w", err)
	}

	// 7. Persist artifacts
	am := &ArtifactManager{
		OutDir:    req.OutDir,
		IOOptions: r.FileOptions,
		Stdout:    req.Stdout,
	}
	artifacts, err := am.PersistVerification(beforeEnv, afterEnv, verification)
	if err != nil {
		return err
	}

	// 8. Build and emit report
	report := r.buildReport(req, verification, artifacts)
	if err := am.PersistReport(&report); err != nil {
		return err
	}
	if !report.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

// --- Internal Workflow Steps ---

func validateLoopDirs(req LoopRequest) error {
	for _, dir := range []struct{ flag, path string }{
		{"--before", req.BeforeDir},
		{"--after", req.AfterDir},
		{"--controls", req.ControlsDir},
	} {
		if err := cmdutil.ValidateFlagDir(dir.flag, dir.path, "", nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) loadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, r.Provider, dir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls in %s", appeval.ErrNoControls, dir)
	}
	return controls, nil
}

func (r *Runner) evaluateState(
	ctx context.Context,
	req LoopRequest,
	controls []policy.ControlDefinition,
	dir string,
	label string,
) (evaluationState, error) {
	loader, err := r.Provider.NewObservationRepo()
	if err != nil {
		return evaluationState{}, fmt.Errorf("%s evaluation: create observation loader: %w", label, err)
	}
	result, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           ctx,
		ObservationsDir:   dir,
		Controls:          controls,
		MaxUnsafe:         req.MaxUnsafe,
		Clock:             r.Clock,
		AllowUnknownType:  req.AllowUnknown,
		ToolVersion:       version.Version,
		ObservationLoader: loader,
	})
	if err != nil {
		return evaluationState{}, fmt.Errorf("%s evaluation: %w", label, err)
	}
	return evaluationState{Result: result, Snapshots: snaps}, nil
}

func (r *Runner) buildReport(req LoopRequest, v safetyenvelope.Verification, artifacts LoopArtifacts) LoopReport {
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
		Before:        observationSummary{Directory: req.BeforeDir, Snapshots: v.Run.BeforeSnapshots, Violations: v.Summary.BeforeViolations},
		After:         observationSummary{Directory: req.AfterDir, Snapshots: v.Run.AfterSnapshots, Violations: v.Summary.AfterViolations},
		Verification:  v.Summary,
		Artifacts:     artifacts,
	}
}

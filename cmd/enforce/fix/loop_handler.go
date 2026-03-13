package fix

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/version"
)

// LoopRequest defines the parameters for a remediation verification lifecycle.
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

type fixLoopObservationSummary struct {
	Directory  string `json:"directory"`
	Snapshots  int    `json:"snapshots"`
	Violations int    `json:"violations"`
}

type fixLoopArtifacts struct {
	BeforeEvaluation string `json:"before_evaluation,omitempty"`
	AfterEvaluation  string `json:"after_evaluation,omitempty"`
	Verification     string `json:"verification,omitempty"`
	Report           string `json:"report,omitempty"`
}

type fixLoopReport struct {
	SchemaVersion kernel.Schema                      `json:"schema_version"`
	Kind          kernel.OutputKind                  `json:"kind"`
	CheckedAt     time.Time                          `json:"checked_at"`
	Pass          bool                               `json:"pass"`
	Reason        string                             `json:"reason"`
	MaxUnsafe     string                             `json:"max_unsafe"`
	Before        fixLoopObservationSummary          `json:"before"`
	After         fixLoopObservationSummary          `json:"after"`
	Verification  safetyenvelope.VerificationSummary `json:"verification"`
	Artifacts     fixLoopArtifacts                   `json:"artifacts"`
}

// Loop executes the apply-before, apply-after, and verify sequence.
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
	execCtx, err := r.prepareLoopExecution(ctx, req)
	if err != nil {
		return err
	}
	controls, err := loadFixLoopControls(ctx, execCtx.controlsDir)
	if err != nil {
		return err
	}
	beforeEval, err := r.evaluateFixLoopState(ctx, execCtx, controls, execCtx.beforeDir, "before")
	if err != nil {
		return err
	}
	afterEval, err := r.evaluateFixLoopState(ctx, execCtx, controls, execCtx.afterDir, "after")
	if err != nil {
		return err
	}

	verification, err := r.buildFixLoopVerification(execCtx, beforeEval, afterEval)
	if err != nil {
		return err
	}
	artifacts, err := r.writeFixLoopArtifacts(execCtx, beforeEval.envelope, afterEval.envelope, verification)
	if err != nil {
		return err
	}

	report := buildFixLoopReport(verification, execCtx.maxUnsafe, execCtx.beforeDir, execCtx.afterDir, artifacts)
	if err := r.writeFixLoopReport(execCtx, &report); err != nil {
		return err
	}
	if !report.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

type fixLoopExecution struct {
	beforeDir    string
	afterDir     string
	controlsDir  string
	outDir       string
	maxUnsafe    time.Duration
	allowUnknown bool
	stdout       io.Writer
}

type fixLoopEvaluation struct {
	result    *evaluation.Result
	snapshots int
	envelope  safetyenvelope.Evaluation
}

func (r *Runner) prepareLoopExecution(_ context.Context, req LoopRequest) (fixLoopExecution, error) {
	if err := validateFixLoopDirs(req); err != nil {
		return fixLoopExecution{}, err
	}
	return fixLoopExecution{
		beforeDir:    req.BeforeDir,
		afterDir:     req.AfterDir,
		controlsDir:  req.ControlsDir,
		outDir:       req.OutDir,
		maxUnsafe:    req.MaxUnsafe,
		allowUnknown: req.AllowUnknown,
		stdout:       req.Stdout,
	}, nil
}

func validateFixLoopDirs(req LoopRequest) error {
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

func loadFixLoopControls(ctx context.Context, controlsDir string) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls in %s", appeval.ErrNoControls, controlsDir)
	}
	return controls, nil
}

func (r *Runner) evaluateFixLoopState(
	ctx context.Context,
	execCtx fixLoopExecution,
	controls []policy.ControlDefinition,
	observationsDir string,
	label string,
) (fixLoopEvaluation, error) {
	loader, err := r.Provider.NewObservationRepo()
	if err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation: create observation loader: %w", label, err)
	}
	result, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           ctx,
		ObservationsDir:   observationsDir,
		Controls:          controls,
		MaxUnsafe:         execCtx.maxUnsafe,
		Clock:             r.Clock,
		AllowUnknownType:  execCtx.allowUnknown,
		ToolVersion:       version.Version,
		ObservationLoader: loader,
	})
	if err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation: %w", label, err)
	}
	env := r.buildEvaluationEnvelope(*result)
	if err := safetyenvelope.ValidateEvaluation(env); err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation schema validation: %w", label, err)
	}
	return fixLoopEvaluation{result: result, snapshots: snaps, envelope: env}, nil
}

func (r *Runner) buildFixLoopVerification(
	execCtx fixLoopExecution,
	beforeEval fixLoopEvaluation,
	afterEval fixLoopEvaluation,
) (safetyenvelope.Verification, error) {
	beforeResult := beforeEval.result
	afterResult := afterEval.result
	now := r.Clock.Now()
	diff := evaluation.CompareVerificationFindings(beforeResult.Findings, afterResult.Findings)
	resolved := shared.FindingsToVerificationEntries(diff.Resolved)
	remaining := shared.FindingsToVerificationEntries(diff.Remaining)
	introduced := shared.FindingsToVerificationEntries(diff.Introduced)
	verification := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{
		Run: safetyenvelope.VerificationRunInfo{
			ToolVersion:     version.Version,
			Offline:         true,
			Now:             now,
			MaxUnsafe:       execCtx.maxUnsafe,
			BeforeSnapshots: beforeEval.snapshots,
			AfterSnapshots:  afterEval.snapshots,
		},
		Summary: safetyenvelope.VerificationSummary{
			BeforeViolations: len(beforeResult.Findings),
			AfterViolations:  len(afterResult.Findings),
			Resolved:         len(resolved),
			Remaining:        len(remaining),
			Introduced:       len(introduced),
		},
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	})
	if err := safetyenvelope.ValidateVerification(verification); err != nil {
		return safetyenvelope.Verification{}, fmt.Errorf("verification schema validation: %w", err)
	}
	return verification, nil
}

func buildFixLoopReport(
	verification safetyenvelope.Verification,
	maxUnsafe time.Duration,
	beforeDir, afterDir string,
	artifacts fixLoopArtifacts,
) fixLoopReport {
	summary := verification.Summary
	run := verification.Run
	pass := summary.Remaining == 0 && summary.Introduced == 0
	reason := "all previously violating resources are now resolved"
	if !pass {
		reason = fmt.Sprintf("remaining=%d introduced=%d", summary.Remaining, summary.Introduced)
	}
	return fixLoopReport{
		SchemaVersion: kernel.SchemaFixLoop,
		Kind:          kernel.KindRemediationReport,
		CheckedAt:     run.Now,
		Pass:          pass,
		Reason:        reason,
		MaxUnsafe:     maxUnsafe.String(),
		Before:        fixLoopObservationSummary{Directory: beforeDir, Snapshots: run.BeforeSnapshots, Violations: summary.BeforeViolations},
		After:         fixLoopObservationSummary{Directory: afterDir, Snapshots: run.AfterSnapshots, Violations: summary.AfterViolations},
		Verification:  summary,
		Artifacts:     artifacts,
	}
}

package fix

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/version"
)

type fixLoopFlagsType struct {
	beforeDir    string
	afterDir     string
	controlsDir  string
	maxUnsafe    string
	now          string
	allowUnknown bool
	outDir       string
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

func runFixLoop(cmd *cobra.Command, flags *fixLoopFlagsType) error {
	execCtx, err := prepareFixLoopExecution(cmd, flags)
	if err != nil {
		return err
	}
	controls, err := loadFixLoopControls(execCtx)
	if err != nil {
		return err
	}
	beforeEval, err := evaluateFixLoopState(cmd, execCtx, controls, execCtx.beforeDir, "before")
	if err != nil {
		return err
	}
	afterEval, err := evaluateFixLoopState(cmd, execCtx, controls, execCtx.afterDir, "after")
	if err != nil {
		return err
	}

	verification, err := buildFixLoopVerification(execCtx, beforeEval, afterEval)
	if err != nil {
		return err
	}
	artifacts, err := writeFixLoopArtifacts(cmd, execCtx, beforeEval.envelope, afterEval.envelope, verification)
	if err != nil {
		return err
	}

	report := buildFixLoopReport(verification, execCtx.maxUnsafe, execCtx.beforeDir, execCtx.afterDir, artifacts)
	if err := writeFixLoopReport(cmd, execCtx, &report); err != nil {
		return err
	}
	if !report.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

type fixLoopExecution struct {
	ctx          context.Context
	beforeDir    string
	afterDir     string
	controlsDir  string
	outDir       string
	maxUnsafe    time.Duration
	clock        ports.Clock
	allowUnknown bool
}

type fixLoopEvaluation struct {
	result    *evaluation.Result
	snapshots int
	envelope  safetyenvelope.Evaluation
}

func prepareFixLoopExecution(cmd *cobra.Command, flags *fixLoopFlagsType) (fixLoopExecution, error) {
	flags.beforeDir = fsutil.CleanUserPath(flags.beforeDir)
	flags.afterDir = fsutil.CleanUserPath(flags.afterDir)
	flags.controlsDir = fsutil.CleanUserPath(flags.controlsDir)
	flags.outDir = fsutil.CleanUserPath(flags.outDir)
	if err := validateFixLoopDirs(flags); err != nil {
		return fixLoopExecution{}, err
	}
	maxDuration, err := timeutil.ParseDurationFlag(flags.maxUnsafe, "--max-unsafe")
	if err != nil {
		return fixLoopExecution{}, err
	}
	clock, err := compose.ResolveClock(flags.now)
	if err != nil {
		return fixLoopExecution{}, err
	}
	return fixLoopExecution{
		ctx:          cmd.Context(),
		beforeDir:    flags.beforeDir,
		afterDir:     flags.afterDir,
		controlsDir:  flags.controlsDir,
		outDir:       flags.outDir,
		maxUnsafe:    maxDuration,
		clock:        clock,
		allowUnknown: flags.allowUnknown,
	}, nil
}

func validateFixLoopDirs(flags *fixLoopFlagsType) error {
	for _, dir := range []struct{ flag, path string }{{"--before", flags.beforeDir}, {"--after", flags.afterDir}, {"--controls", flags.controlsDir}} {
		if err := cmdutil.ValidateDir(dir.flag, dir.path, nil); err != nil {
			return err
		}
	}
	return nil
}

func loadFixLoopControls(execCtx fixLoopExecution) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(execCtx.ctx, execCtx.controlsDir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("no controls in %s", execCtx.controlsDir)
	}
	return controls, nil
}

func evaluateFixLoopState(
	cmd *cobra.Command,
	execCtx fixLoopExecution,
	controls []policy.ControlDefinition,
	observationsDir string,
	label string,
) (fixLoopEvaluation, error) {
	loader, err := compose.NewObservationRepository()
	if err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation: create observation loader: %w", label, err)
	}
	result, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           execCtx.ctx,
		ObservationsDir:   observationsDir,
		Controls:          controls,
		MaxUnsafe:         execCtx.maxUnsafe,
		Clock:             execCtx.clock,
		AllowUnknownType:  execCtx.allowUnknown,
		ToolVersion:       version.Version,
		ObservationLoader: loader,
	})
	if err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation: %w", label, err)
	}
	env := buildEvaluationEnvelope(cmd, *result)
	if err := safetyenvelope.ValidateEvaluation(env); err != nil {
		return fixLoopEvaluation{}, fmt.Errorf("%s evaluation schema validation: %w", label, err)
	}
	return fixLoopEvaluation{result: result, snapshots: snaps, envelope: env}, nil
}

func buildFixLoopVerification(
	execCtx fixLoopExecution,
	beforeEval fixLoopEvaluation,
	afterEval fixLoopEvaluation,
) (safetyenvelope.Verification, error) {
	beforeResult := beforeEval.result
	afterResult := afterEval.result
	now := execCtx.clock.Now()
	diff := evaluation.CompareVerificationFindings(beforeResult.Findings, afterResult.Findings)
	resolved := shared.FindingsToVerificationEntries(diff.Resolved)
	remaining := shared.FindingsToVerificationEntries(diff.Remaining)
	introduced := shared.FindingsToVerificationEntries(diff.Introduced)
	verification := safetyenvelope.Verification{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          safetyenvelope.KindVerification,
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
	}
	verification.Normalize()
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

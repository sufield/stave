package fix

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
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

var (
	fixLoopBeforeDir    string
	fixLoopAfterDir     string
	fixLoopControlsDir  string
	fixLoopMaxUnsafe    string
	fixLoopNow          string
	fixLoopAllowUnknown bool
	fixLoopOutDir       string
)

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
	Kind          string                             `json:"kind"`
	CheckedAt     time.Time                          `json:"checked_at"`
	Pass          bool                               `json:"pass"`
	Reason        string                             `json:"reason"`
	MaxUnsafe     string                             `json:"max_unsafe"`
	Before        fixLoopObservationSummary          `json:"before"`
	After         fixLoopObservationSummary          `json:"after"`
	Verification  safetyenvelope.VerificationSummary `json:"verification"`
	Artifacts     fixLoopArtifacts                   `json:"artifacts"`
}

func runFixLoop(cmd *cobra.Command, _ []string) error {
	execCtx, err := prepareFixLoopExecution()
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

	report := buildFixLoopReport(verification, execCtx.maxUnsafe, artifacts)
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

func prepareFixLoopExecution() (fixLoopExecution, error) {
	fixLoopBeforeDir = fsutil.CleanUserPath(fixLoopBeforeDir)
	fixLoopAfterDir = fsutil.CleanUserPath(fixLoopAfterDir)
	fixLoopControlsDir = fsutil.CleanUserPath(fixLoopControlsDir)
	fixLoopOutDir = fsutil.CleanUserPath(fixLoopOutDir)
	if err := validateFixLoopDirs(); err != nil {
		return fixLoopExecution{}, err
	}
	maxDuration, err := timeutil.ParseDurationFlag(fixLoopMaxUnsafe, "--max-unsafe")
	if err != nil {
		return fixLoopExecution{}, err
	}
	clock, err := cmdutil.ResolveClock(fixLoopNow)
	if err != nil {
		return fixLoopExecution{}, err
	}
	return fixLoopExecution{
		ctx:          context.Background(),
		beforeDir:    fixLoopBeforeDir,
		afterDir:     fixLoopAfterDir,
		controlsDir:  fixLoopControlsDir,
		outDir:       fixLoopOutDir,
		maxUnsafe:    maxDuration,
		clock:        clock,
		allowUnknown: fixLoopAllowUnknown,
	}, nil
}

func validateFixLoopDirs() error {
	for _, dir := range []struct{ flag, path string }{{"--before", fixLoopBeforeDir}, {"--after", fixLoopAfterDir}, {"--controls", fixLoopControlsDir}} {
		fi, err := os.Stat(dir.path)
		if err != nil {
			return ui.DirectoryAccessError(dir.flag, dir.path, err, nil)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s must be a directory: %s", dir.flag, dir.path)
		}
	}
	return nil
}

func loadFixLoopControls(execCtx fixLoopExecution) ([]policy.ControlDefinition, error) {
	ctlLoader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlLoader.LoadControls(execCtx.ctx, execCtx.controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
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
	loader, err := cmdutil.NewObservationRepository()
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
	resolved := findingsToEntries(diff.Resolved)
	remaining := findingsToEntries(diff.Remaining)
	introduced := findingsToEntries(diff.Introduced)
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
		Kind:          "remediation_report",
		CheckedAt:     run.Now,
		Pass:          pass,
		Reason:        reason,
		MaxUnsafe:     maxUnsafe.String(),
		Before:        fixLoopObservationSummary{Directory: fixLoopBeforeDir, Snapshots: run.BeforeSnapshots, Violations: summary.BeforeViolations},
		After:         fixLoopObservationSummary{Directory: fixLoopAfterDir, Snapshots: run.AfterSnapshots, Violations: summary.AfterViolations},
		Verification:  summary,
		Artifacts:     artifacts,
	}
}

func findingsToEntries(findings []evaluation.Finding) []safetyenvelope.VerificationEntry {
	entries := make([]safetyenvelope.VerificationEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, safetyenvelope.VerificationEntry{
			ControlID:   f.ControlID,
			ControlName: f.ControlName,
			AssetID:     f.AssetID,
			AssetType:   f.AssetType,
		})
	}
	return entries
}

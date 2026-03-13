package verify

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/shared"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/sanitize"
	staveversion "github.com/sufield/stave/internal/version"
)

// verifyExecution holds parsed runtime parameters for the verification run.
type verifyExecution struct {
	ctx          context.Context
	maxUnsafe    time.Duration
	clock        ports.Clock
	allowUnknown bool
}

func runVerify(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	// 1. Parse runtime parameters
	maxUnsafe, clock, err := parseRuntime(opts)
	if err != nil {
		return err
	}

	ctx := compose.CommandContext(cmd)
	controls, err := loadVerifyControls(ctx, opts.ControlsDir)
	if err != nil {
		return err
	}

	execCtx := verifyExecution{
		ctx:          ctx,
		maxUnsafe:    maxUnsafe,
		clock:        clock,
		allowUnknown: opts.AllowUnknown,
	}

	// 2. Run evaluations
	rt.Quiet = opts.Quiet || cmdutil.QuietEnabled(cmd)

	beforeDone := rt.BeginProgress("apply before observations")
	beforeEval, err := runVerifyEvaluation(execCtx, controls, opts.BeforeDir)
	beforeDone()
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	afterDone := rt.BeginProgress("apply after observations")
	afterEval, err := runVerifyEvaluation(execCtx, controls, opts.AfterDir)
	afterDone()
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	// 3. Build and write output
	outcome := buildVerificationOutcome(cmd, execCtx, beforeEval, afterEval)
	if err := writeVerificationJSON(cmd.OutOrStdout(), outcome.result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return verifyOutcomeExit(rt, outcome)
}

// parseRuntime converts raw option strings into structured runtime values.
func parseRuntime(opts *options) (time.Duration, ports.Clock, error) {
	maxDuration, err := timeutil.ParseDurationFlag(opts.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return 0, nil, err
	}
	clock, err := compose.ResolveClock(opts.NowTime)
	if err != nil {
		return 0, nil, err
	}
	return maxDuration, clock, nil
}

type verifyEvaluation struct {
	result        *evaluation.Result
	snapshotCount int
}

type verifyOutcome struct {
	result          safetyenvelope.Verification
	remainingCount  int
	introducedCount int
}

func loadVerifyControls(ctx context.Context, controlsDir string) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls in %s", appeval.ErrNoControls, controlsDir)
	}
	return controls, nil
}

func runVerifyEvaluation(execCtx verifyExecution, controls []policy.ControlDefinition, observationsDir string) (verifyEvaluation, error) {
	result, snaps, err := runEvaluation(runEvaluationRequest{
		Context:          execCtx.ctx,
		ObservationsDir:  observationsDir,
		Controls:         controls,
		MaxUnsafe:        execCtx.maxUnsafe,
		Clock:            execCtx.clock,
		AllowUnknownType: execCtx.allowUnknown,
	})
	if err != nil {
		return verifyEvaluation{}, err
	}
	return verifyEvaluation{result: result, snapshotCount: snaps}, nil
}

func buildVerificationOutcome(cmd *cobra.Command, execCtx verifyExecution, before, after verifyEvaluation) verifyOutcome {
	diff := evaluation.CompareVerificationFindings(before.result.Findings, after.result.Findings)
	sanitizer := cmdutil.GetSanitizer(cmd)
	resolved := redactVerificationEntries(sanitizer, shared.FindingsToVerificationEntries(diff.Resolved))
	remaining := redactVerificationEntries(sanitizer, shared.FindingsToVerificationEntries(diff.Remaining))
	introduced := redactVerificationEntries(sanitizer, shared.FindingsToVerificationEntries(diff.Introduced))

	result := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{
		Run: safetyenvelope.VerificationRunInfo{
			ToolVersion:     staveversion.Version,
			Offline:         true,
			Now:             execCtx.clock.Now(),
			MaxUnsafe:       execCtx.maxUnsafe,
			BeforeSnapshots: before.snapshotCount,
			AfterSnapshots:  after.snapshotCount,
		},
		Summary: safetyenvelope.VerificationSummary{
			BeforeViolations: len(before.result.Findings),
			AfterViolations:  len(after.result.Findings),
			Resolved:         len(resolved),
			Remaining:        len(remaining),
			Introduced:       len(introduced),
		},
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	})
	return verifyOutcome{
		result:          result,
		remainingCount:  len(remaining),
		introducedCount: len(introduced),
	}
}

func redactVerificationEntries(sanitizer *sanitize.Sanitizer, entries []safetyenvelope.VerificationEntry) []safetyenvelope.VerificationEntry {
	out := make([]safetyenvelope.VerificationEntry, len(entries))
	for i, e := range entries {
		out[i] = e
		out[i].AssetID = sanitizer.Verification(e.AssetID)
	}
	return out
}

func verifyOutcomeExit(rt *ui.Runtime, outcome verifyOutcome) error {
	if outcome.remainingCount > 0 || outcome.introducedCount > 0 {
		rt.PrintNextSteps(
			"Run `stave diagnose` against the after observations to understand remaining violations.",
			"Run `stave ci fix-loop` for automated before/after comparison with detailed reports.",
		)
		return ui.ErrViolationsFound
	}
	return nil
}

type runEvaluationRequest struct {
	Context          context.Context
	ObservationsDir  string
	Controls         []policy.ControlDefinition
	MaxUnsafe        time.Duration
	Clock            ports.Clock
	AllowUnknownType bool
}

func runEvaluation(req runEvaluationRequest) (*evaluation.Result, int, error) {
	loader, err := compose.NewObservationRepository()
	if err != nil {
		return nil, 0, fmt.Errorf("create observation loader: %w", err)
	}
	return appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           req.Context,
		ObservationsDir:   req.ObservationsDir,
		Controls:          req.Controls,
		MaxUnsafe:         req.MaxUnsafe,
		Clock:             req.Clock,
		AllowUnknownType:  req.AllowUnknownType,
		ToolVersion:       staveversion.Version,
		ObservationLoader: loader,
	})
}

func writeVerificationJSON(w io.Writer, result safetyenvelope.Verification) error {
	return outjson.WriteVerification(w, result)
}

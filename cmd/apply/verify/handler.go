package verify

import (
	"context"
	"fmt"
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

// runVerify is the top-level CLI orchestrator.
func runVerify(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	// 1. Prepare environment and dependencies
	maxUnsafe, clock, err := parseRuntime(opts)
	if err != nil {
		return err
	}

	ctx := compose.CommandContext(cmd)
	sanitizer := cmdutil.GetSanitizer(cmd)
	rt.Quiet = opts.Quiet || cmdutil.QuietEnabled(cmd)

	// 2. Load Control Definitions
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

	// 3. Run Evaluations
	before, err := runStep(rt, "apply before observations", func() (evalResult, error) {
		return runVerifyEvaluation(execCtx, controls, opts.BeforeDir)
	})
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	after, err := runStep(rt, "apply after observations", func() (evalResult, error) {
		return runVerifyEvaluation(execCtx, controls, opts.AfterDir)
	})
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	// 4. Compare and Construct Outcome
	outcome := compareEvaluations(execCtx, before, after, sanitizer)

	// 5. Report Results
	if err := outjson.WriteVerification(cmd.OutOrStdout(), outcome.Envelope); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return handleVerifyExit(rt, outcome)
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

// --- Internal Business Logic ---

type evalResult struct {
	result        *evaluation.Result
	snapshotCount int
}

type verificationOutcome struct {
	Envelope        safetyenvelope.Verification
	RemainingCount  int
	IntroducedCount int
}

func loadVerifyControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls found in %s", appeval.ErrNoControls, dir)
	}
	return controls, nil
}

func compareEvaluations(
	exec verifyExecution,
	before, after evalResult,
	sz *sanitize.Sanitizer,
) verificationOutcome {
	diff := evaluation.CompareVerificationFindings(before.result.Findings, after.result.Findings)

	resolved := redactEntries(sz, shared.FindingsToVerificationEntries(diff.Resolved))
	remaining := redactEntries(sz, shared.FindingsToVerificationEntries(diff.Remaining))
	introduced := redactEntries(sz, shared.FindingsToVerificationEntries(diff.Introduced))

	envelope := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{
		Run: safetyenvelope.VerificationRunInfo{
			ToolVersion:     staveversion.Version,
			Offline:         true,
			Now:             exec.clock.Now(),
			MaxUnsafe:       exec.maxUnsafe,
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

	return verificationOutcome{
		Envelope:        envelope,
		RemainingCount:  len(remaining),
		IntroducedCount: len(introduced),
	}
}

// redactEntries returns a new slice with sensitive fields (AssetID) sanitized.
func redactEntries(sz *sanitize.Sanitizer, entries []safetyenvelope.VerificationEntry) []safetyenvelope.VerificationEntry {
	out := make([]safetyenvelope.VerificationEntry, len(entries))
	for i, e := range entries {
		e.AssetID = sz.Verification(e.AssetID)
		out[i] = e
	}
	return out
}

func handleVerifyExit(rt *ui.Runtime, outcome verificationOutcome) error {
	if outcome.RemainingCount == 0 && outcome.IntroducedCount == 0 {
		return nil
	}

	rt.PrintNextSteps(
		"Run `stave diagnose` against the after observations to investigate remaining violations.",
		"Check `introduced` findings to ensure remediation didn't create new security gaps.",
	)

	return ui.ErrViolationsFound
}

// --- Helpers ---

// runStep wraps a task with a progress indicator.
func runStep[T any](rt *ui.Runtime, label string, fn func() (T, error)) (T, error) {
	done := rt.BeginProgress(label)
	res, err := fn()
	done()
	return res, err
}

func runVerifyEvaluation(exec verifyExecution, controls []policy.ControlDefinition, obsDir string) (evalResult, error) {
	loader, err := compose.NewObservationRepository()
	if err != nil {
		return evalResult{}, err
	}

	res, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           exec.ctx,
		ObservationsDir:   obsDir,
		Controls:          controls,
		MaxUnsafe:         exec.maxUnsafe,
		Clock:             exec.clock,
		AllowUnknownType:  exec.allowUnknown,
		ToolVersion:       staveversion.Version,
		ObservationLoader: loader,
	})
	if err != nil {
		return evalResult{}, err
	}
	return evalResult{result: res, snapshotCount: snaps}, nil
}

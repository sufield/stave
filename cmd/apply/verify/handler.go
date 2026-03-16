package verify

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/shared"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/safetyenvelope"
	staveversion "github.com/sufield/stave/internal/version"
)

// runVerify is the top-level CLI orchestrator.
func runVerify(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	// 1. Prepare environment and dependencies
	exec, err := opts.Complete(compose.CommandContext(cmd))
	if err != nil {
		return err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	sanitizer := gf.GetSanitizer()
	rt.Quiet = gf.Quiet

	// 2. Load Control Definitions
	controls, err := loadVerifyControls(exec.Context, exec.ControlsDir)
	if err != nil {
		return err
	}

	// 3. Run Evaluations
	before, err := runStep(rt, "apply before observations", func() (evalResult, error) {
		return runVerifyEvaluation(exec, controls, exec.BeforeDir)
	})
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	after, err := runStep(rt, "apply after observations", func() (evalResult, error) {
		return runVerifyEvaluation(exec, controls, exec.AfterDir)
	})
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	// 4. Compare and Construct Outcome
	outcome := compareEvaluations(exec, before, after, sanitizer)

	// 5. Report Results
	if err := outjson.WriteVerification(cmd.OutOrStdout(), outcome.Envelope); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return handleVerifyExit(rt, outcome)
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
	exec Execution,
	before, after evalResult,
	sz kernel.Sanitizer,
) verificationOutcome {
	diff := evaluation.CompareVerificationFindings(before.result.Findings, after.result.Findings)

	resolved := shared.FindingsToVerificationEntries(sz, diff.Resolved)
	remaining := shared.FindingsToVerificationEntries(sz, diff.Remaining)
	introduced := shared.FindingsToVerificationEntries(sz, diff.Introduced)

	envelope := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{
		Run: safetyenvelope.VerificationRunInfo{
			ToolVersion:     staveversion.Version,
			Offline:         true,
			Now:             exec.Clock.Now(),
			MaxUnsafe:       exec.MaxUnsafe,
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

func runVerifyEvaluation(exec Execution, controls []policy.ControlDefinition, obsDir string) (evalResult, error) {
	loader, err := compose.ActiveProvider().NewObservationRepo()
	if err != nil {
		return evalResult{}, err
	}

	res, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           exec.Context,
		ObservationsDir:   obsDir,
		Controls:          controls,
		MaxUnsafe:         exec.MaxUnsafe,
		Clock:             exec.Clock,
		AllowUnknownType:  exec.AllowUnknown,
		ToolVersion:       staveversion.Version,
		ObservationLoader: loader,
	})
	if err != nil {
		return evalResult{}, err
	}
	return evalResult{result: res, snapshotCount: snaps}, nil
}

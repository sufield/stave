package verify

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	appeval "github.com/sufield/stave/internal/app/eval"
	appverify "github.com/sufield/stave/internal/app/verify"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	staveversion "github.com/sufield/stave/internal/version"
)

// runVerify is the top-level CLI orchestrator.
func runVerify(cmd *cobra.Command, p *compose.Provider, rt *ui.Runtime, opts *options) error {
	// 1. Prepare environment and dependencies
	exec, err := opts.Complete(compose.CommandContext(cmd))
	if err != nil {
		return err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	sanitizer := gf.GetSanitizer()
	rt.Quiet = gf.Quiet

	// 2. Load Control Definitions
	controls, err := loadVerifyControls(exec.Context, p, exec.ControlsDir)
	if err != nil {
		return err
	}

	// 3. Run Evaluations
	before, err := runStep(rt, "apply before observations", func() (evalResult, error) {
		return runVerifyEvaluation(p, exec, controls, exec.BeforeDir)
	})
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	after, err := runStep(rt, "apply after observations", func() (evalResult, error) {
		return runVerifyEvaluation(p, exec, controls, exec.AfterDir)
	})
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	// 4. Compare and Construct Outcome
	cmp, err := appverify.Compare(appverify.CompareRequest{
		BeforeFindings:  before.result.Findings,
		AfterFindings:   after.result.Findings,
		BeforeSnapshots: before.snapshotCount,
		AfterSnapshots:  after.snapshotCount,
		MaxUnsafe:       exec.MaxUnsafe,
		Now:             exec.Clock.Now(),
		Sanitizer:       sanitizer,
	})
	if err != nil {
		return err
	}

	// 5. Report Results
	if err := outjson.WriteVerification(cmd.OutOrStdout(), cmp.Verification); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return handleVerifyExit(rt, cmp)
}

// --- Internal Business Logic ---

type evalResult struct {
	result        *evaluation.Result
	snapshotCount int
}

func loadVerifyControls(ctx context.Context, p *compose.Provider, dir string) ([]policy.ControlDefinition, error) {
	controls, err := compose.LoadControls(ctx, p, dir)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("%w: no controls found in %s", appeval.ErrNoControls, dir)
	}
	return controls, nil
}

func handleVerifyExit(rt *ui.Runtime, outcome appverify.CompareResult) error {
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

func runVerifyEvaluation(p *compose.Provider, exec Execution, controls []policy.ControlDefinition, obsDir string) (evalResult, error) {
	loader, err := p.NewObservationRepo()
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

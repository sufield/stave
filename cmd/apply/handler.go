package apply

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
)

// runApplyCore gathers validated options, then dispatches by mode.
func runApplyCore(cmd *cobra.Command, flags *applyFlagsType) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	opts, err := gatherRunOptions(cmd, flags)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}

	switch opts.mode {
	case runModeProfile:
		return runApplyProfileWithOptions(cmd, opts.profile)
	default:
		return runStandardApply(cmd, flags, opts)
	}
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(cmd *cobra.Command, flags *applyFlagsType, opts runOptions) error {
	plan, err := appeval.NewPlan(opts.evaluatorInput)
	if err != nil {
		return ui.EvaluateErrorWithHint(fmt.Errorf("failed to resolve evaluation plan: %w", err))
	}
	cmdutil.AttachRunIDFromPlan(plan)

	results, err := executeApply(cmd, cmd.Context(), flags, opts, plan)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}

	return outputResults(cmd, results)
}

func runStrictIntegrityCheck(cmd *cobra.Command) error {
	rt := ui.NewRuntime(cmd.OutOrStdout(), cmd.ErrOrStderr())
	rt.Quiet = cmdutil.QuietEnabled(cmd)
	rt.Strict = cmdutil.StrictEnabled(cmd)
	if !rt.Strict {
		return nil
	}

	done := rt.BeginProgress("perform strict integrity checks")
	defer done()

	reg, err := packs.DefaultRegistry()
	if err != nil {
		return fmt.Errorf("load default pack registry: %w", err)
	}
	if err := reg.ValidateStrict(ctlbuiltin.EmbeddedFS()); err != nil {
		return ui.WithNextCommand(err, "stave packs list")
	}
	return nil
}

func executeApply(
	cmd *cobra.Command,
	ctx context.Context,
	flags *applyFlagsType,
	opts runOptions,
	plan *appeval.EvaluationPlan,
) (EvaluateResult, error) {
	deps, err := NewFactory(cmd, flags, opts.params).Build(plan)
	if err != nil {
		return EvaluateResult{}, err
	}
	defer deps.Close()

	progress := ui.DefaultRuntime()
	progress.Quiet = cmdutil.QuietEnabled(cmd)
	done := progress.BeginProgress("apply controls against observations")
	defer done()

	status, err := appeval.Run(ctx, appeval.RunInput{
		Runner: deps.Runner,
		Config: deps.Config,
	})
	if err != nil {
		return EvaluateResult{}, err
	}
	return BuildEvaluateResult(status, deps.Config.ControlsDir, deps.Config.ObservationsDir), nil
}

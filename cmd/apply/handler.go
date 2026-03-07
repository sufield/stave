package apply

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
)

// runApplyCore is the core handler for the apply command.
// It validates flags, builds dependencies, and runs the evaluation.
func runApplyCore(cmd *cobra.Command, _ []string) error {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return err
	}

	opts, err := gatherRunOptions(cmd)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}
	if strictErr := runStrictIntegrityCheck(cmd); strictErr != nil {
		return ui.EvaluateErrorWithHint(strictErr)
	}

	switch opts.mode {
	case runModeProfile:
		return runApplyProfileWithOptions(cmd, opts.profile)
	case runModeTemplate:
		return runApplyWithTemplateParams(cmd, opts.params)
	}

	plan, err := appeval.NewPlan(opts.evaluatorInput)
	if err != nil {
		return ui.EvaluateErrorWithHint(fmt.Errorf("failed to resolve evaluation plan: %w", err))
	}
	attachRunIDFromPlan(plan)

	if opts.explain {
		fmt.Fprintln(cmd.ErrOrStderr(), plan.Summary())
	}
	if opts.dryRun {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}

	results, err := executeApply(cmd, cmd.Context(), opts, plan)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}

	return outputResults(cmd, results, opts.format)
}

func runStrictIntegrityCheck(cmd *cobra.Command) error {
	rt := ui.NewRuntime(cmd.OutOrStdout(), cmd.ErrOrStderr())
	rt.Quiet = applyFlags.quietMode
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
	opts runOptions,
	plan *appeval.EvaluationPlan,
) (EvaluateResult, error) {
	deps, err := NewFactory(cmd, opts.params).Build(plan)
	if err != nil {
		return EvaluateResult{}, err
	}
	defer deps.Close()

	progress := ui.NewRuntime(nil, nil)
	progress.Quiet = applyFlags.quietMode
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

package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// runApplyCore gathers validated options, then dispatches by mode.
func runApplyCore(cmd *cobra.Command, flags *applyFlagsType) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	opts, err := gatherRunOptions(cmd, flags)
	if err != nil {
		return ui.EvaluateErrorWithHint(attachDomainHints(err))
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
		return ui.EvaluateErrorWithHint(attachDomainHints(fmt.Errorf("failed to resolve evaluation plan: %w", err)))
	}
	cmdutil.AttachRunIDFromPlan(plan)

	results, err := executeApply(cmd, cmd.Context(), flags, opts, plan)
	if err != nil {
		return ui.EvaluateErrorWithHint(attachDomainHints(err))
	}

	return outputResults(cmd, results)
}

func runStrictIntegrityCheck(cmd *cobra.Command) error {
	rt := cmdutil.NewRuntime(cmd)
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

// attachDomainHints decorates known domain sentinel errors with hint sentinels
// so the hint system resolves via the sentinel-first path rather than string fallback.
func attachDomainHints(err error) error {
	switch {
	case errors.Is(err, appeval.ErrNoControls):
		return ui.WithHint(err, ui.ErrHintNoControls)
	case errors.Is(err, appeval.ErrNoSnapshots):
		return ui.WithHint(err, ui.ErrHintNoSnapshots)
	case errors.Is(err, appeval.ErrSourceTypeMissing),
		errors.Is(err, appeval.ErrSourceTypeUnsupported):
		return ui.WithHint(err, ui.ErrHintSourceType)
	case errors.Is(err, contractvalidator.ErrSchemaValidationFailed):
		return ui.WithHint(err, ui.ErrHintSchemaValidation)
	default:
		return err
	}
}

func executeApply(
	cmd *cobra.Command,
	ctx context.Context,
	flags *applyFlagsType,
	opts runOptions,
	plan *appeval.EvaluationPlan,
) (EvaluateResult, error) {
	rt := cmdutil.NewRuntime(cmd)
	progress := rt.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	factory := NewFactory(cmd, flags, opts.params)
	factory.OnObsProgress = progress.Update

	deps, err := factory.Build(plan)
	if err != nil {
		return EvaluateResult{}, err
	}
	defer deps.Close()

	status, err := appeval.Run(ctx, appeval.RunInput{
		Runner: deps.Runner,
		Config: deps.Config,
	})
	if err != nil {
		return EvaluateResult{}, err
	}
	return BuildEvaluateResult(status, deps.Config.ControlsDir, deps.Config.ObservationsDir), nil
}

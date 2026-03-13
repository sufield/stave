package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// runApplyCore gathers validated options, then dispatches by mode.
func runApplyCore(cmd *cobra.Command, opts *ApplyOptions) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	runOpts, err := gatherRunOptions(cmd, opts)
	if err != nil {
		return ui.EvaluateErrorWithHint(attachDomainHints(err))
	}

	switch runOpts.mode {
	case runModeProfile:
		return runApplyProfileWithOptions(cmd, runOpts.profile)
	default:
		return runStandardApply(cmd, opts, runOpts)
	}
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(cmd *cobra.Command, opts *ApplyOptions, runOpts runOptions) error {
	plan, err := appeval.NewPlan(runOpts.evaluatorInput)
	if err != nil {
		return ui.EvaluateErrorWithHint(attachDomainHints(fmt.Errorf("failed to resolve evaluation plan: %w", err)))
	}
	cmdutil.AttachRunIDFromPlan(plan)

	results, err := executeApply(cmd, cmd.Context(), opts, runOpts, plan)
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
	opts *ApplyOptions,
	runOpts runOptions,
	plan *appeval.EvaluationPlan,
) (EvaluateResult, error) {
	rt := cmdutil.NewRuntime(cmd)
	progress := rt.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	builder := &Builder{
		Ctx:           ctx,
		Stdout:        compose.ResolveStdout(cmd, cmdutil.QuietEnabled(cmd), runOpts.format),
		Stderr:        cmd.ErrOrStderr(),
		Sanitizer:     cmdutil.GetSanitizer(cmd),
		IsJSON:        cmdutil.IsJSONMode(cmd),
		Opts:          opts,
		Params:        runOpts.params,
		OnObsProgress: progress.Update,
	}

	deps, err := builder.Build(plan)
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

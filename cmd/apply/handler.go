package apply

import (
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

// runApply is the main entry point for the apply command.
func runApply(cmd *cobra.Command, _ []string, opts *ApplyOptions) error {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return err
	}
	if _, err = resolver.ResolveSelected(); err != nil {
		return err
	}

	if err = runStrictIntegrityCheck(cmd); err != nil {
		return err
	}

	cfg, err := opts.Resolve(cmd)
	if err != nil {
		return decorateError(err)
	}

	if cfg.Mode == runModeProfile {
		return runProfileApply(cmd, cfg.Profile)
	}

	return runStandardApply(cmd, opts, cfg.Params)
}

// runProfileApply bridges the Cobra layer into the Runner/Config pattern.
func runProfileApply(cmd *cobra.Command, cfg Config) error {
	clock, err := compose.ResolveClock(cfg.NowTime)
	if err != nil {
		return err
	}

	format, err := compose.ResolveFormatValue(cmd, cfg.OutputFormat)
	if err != nil {
		return err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	cfg.Stdout = compose.ResolveStdout(cmd.OutOrStdout(), cfg.Quiet, format)
	cfg.Stderr = cmd.ErrOrStderr()
	cfg.IsJSONMode = gf.IsJSONMode()
	cfg.Sanitizer = gf.GetSanitizer()
	cfg.OutputFormat = format.String()

	runner := NewRunner(clock, cfg.Quiet)
	return runner.Run(cmd.Context(), cfg)
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(cmd *cobra.Command, opts *ApplyOptions, params applyParams) error {
	plan, err := appeval.NewPlan(opts.buildEvaluatorInput())
	if err != nil {
		return decorateError(fmt.Errorf("failed to resolve evaluation plan: %w", err))
	}
	cmdutil.AttachRunIDFromPlan(plan)

	results, err := executeEvaluation(cmd, opts, params, plan)
	if err != nil {
		return decorateError(err)
	}

	rep := &Reporter{
		Stdout: cmd.OutOrStdout(),
		Stderr: cmd.ErrOrStderr(),
		Quiet:  cmdutil.GetGlobalFlags(cmd).Quiet,
	}
	return rep.ReportApply(results)
}

func executeEvaluation(
	cmd *cobra.Command,
	opts *ApplyOptions,
	params applyParams,
	plan *appeval.EvaluationPlan,
) (EvaluateResult, error) {
	gf := cmdutil.GetGlobalFlags(cmd)
	rt := cmdutil.NewRuntime(cmd)
	progress := rt.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	format, _ := compose.ResolveFormatValue(cmd, opts.Format)

	builder := &Builder{
		Ctx:           cmd.Context(),
		Stdout:        compose.ResolveStdout(cmd.OutOrStdout(), gf.Quiet, format),
		Stderr:        cmd.ErrOrStderr(),
		Sanitizer:     gf.GetSanitizer(),
		IsJSON:        gf.IsJSONMode(),
		Opts:          opts,
		Params:        params,
		OnObsProgress: progress.Update,
	}

	deps, err := builder.Build(plan)
	if err != nil {
		return EvaluateResult{}, err
	}
	defer deps.Close()

	status, err := appeval.Run(cmd.Context(), appeval.RunInput{
		Runner: deps.Runner,
		Config: deps.Config,
	})
	if err != nil {
		return EvaluateResult{}, err
	}

	return BuildEvaluateResult(status, deps.Config.ControlsDir, deps.Config.ObservationsDir), nil
}

// runStrictIntegrityCheck ensures internal pack integrity when --strict is set.
func runStrictIntegrityCheck(cmd *cobra.Command) error {
	if !cmdutil.GetGlobalFlags(cmd).Strict {
		return nil
	}

	rt := cmdutil.NewRuntime(cmd)
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

// decorateError maps domain-specific errors to user-facing remediation hints.
func decorateError(err error) error {
	var hint error
	switch {
	case errors.Is(err, appeval.ErrNoControls):
		hint = ui.ErrHintNoControls
	case errors.Is(err, appeval.ErrNoSnapshots):
		hint = ui.ErrHintNoSnapshots
	case errors.Is(err, appeval.ErrSourceTypeMissing),
		errors.Is(err, appeval.ErrSourceTypeUnsupported):
		hint = ui.ErrHintSourceType
	case errors.Is(err, contractvalidator.ErrSchemaValidationFailed):
		hint = ui.ErrHintSchemaValidation
	default:
		return err
	}
	return ui.EvaluateErrorWithHint(ui.WithHint(err, hint))
}

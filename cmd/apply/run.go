package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/logging"
)

// runApply is the single dispatch function called by the thin RunE wrapper.
// All cobra state has already been extracted into cs.
func runApply(p *compose.Provider, opts *ApplyOptions, cs cobraState) error {
	if err := opts.validate(); err != nil {
		return fmt.Errorf("validate options: %w", err)
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}
	if _, err = resolver.ResolveSelected(); err != nil {
		return fmt.Errorf("resolve selected context: %w", err)
	}

	if opts.DryRun {
		planCfg, planErr := opts.ResolveDryRun(cs)
		if planErr != nil {
			return fmt.Errorf("resolve dry-run config: %w", planErr)
		}
		return runDryRun(cs.Ctx, p, planCfg)
	}

	if err = runStrictIntegrityCheck(cs.GlobalFlags.Strict, cs.Stdout, cs.Stderr); err != nil {
		return err // already wrapped inside runStrictIntegrityCheck
	}

	cfg, err := opts.Resolve(cs)
	if err != nil {
		return decorateError(err)
	}

	if cfg.Mode == runModeProfile {
		rt := ui.NewRuntime(cs.Stdout, cs.Stderr)
		rt.Quiet = cfg.Profile.Quiet
		runner := NewRunner(p, cfg.profileClock, rt)
		return runner.Run(cs.Ctx, cfg.Profile)
	}

	sio, err := opts.ResolveStandardIO(cs)
	if err != nil {
		return fmt.Errorf("resolve output config: %w", err)
	}
	return runStandardApply(cs.Ctx, p, opts, cfg.Params, sio)
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(ctx context.Context, p *compose.Provider, opts *ApplyOptions, params applyParams, sio standardIO) error {
	evalInput, err := opts.buildEvaluatorInput()
	if err != nil {
		return decorateError(fmt.Errorf("failed to build evaluator input: %w", err))
	}
	plan, err := appeval.NewPlan(evalInput)
	if err != nil {
		return decorateError(fmt.Errorf("failed to resolve evaluation plan: %w", err))
	}

	logger := logging.DefaultLogger()
	if plan != nil {
		logger = cmdutil.SetupLoggingWithRunID(logger, plan.ObservationsHash.String(), plan.ControlsHash.String())
	}

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	results, err := executeEvaluation(ctx, p, opts, params, sio, plan, rt, logger)
	if err != nil {
		return decorateError(err)
	}

	rep := &Reporter{Stdout: sio.Stdout, Stderr: sio.Stderr, Runtime: rt, Quiet: sio.Quiet}
	return rep.ReportApply(results)
}

func executeEvaluation(
	ctx context.Context,
	p *compose.Provider,
	opts *ApplyOptions,
	params applyParams,
	sio standardIO,
	plan *appeval.EvaluationPlan,
	rt *ui.Runtime,
	logger *slog.Logger,
) (EvaluateResult, error) {
	progress := rt.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	builder := NewBuilder(ctx, logger, p, opts, params, sio)
	builder.OnObsProgress = progress.Update

	deps, err := builder.Build(plan)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("build evaluation dependencies: %w", err)
	}
	defer deps.Close()

	result, status, err := deps.Runner.ExecuteAndReturn(ctx, deps.Config)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: %w", err)
	}

	if err := appeval.RunOutputPipeline(ctx, deps.Config.Output, result, deps.Runner.Marshaler, deps.Runner.EnrichFn, logger); err != nil {
		return EvaluateResult{}, fmt.Errorf("run output pipeline: %w", err)
	}

	return BuildEvaluateResult(status, deps.Config.ControlsDir, deps.Config.ObservationsDir), nil
}

// runStrictIntegrityCheck ensures internal pack integrity when --strict is set.
func runStrictIntegrityCheck(strict bool, stdout, stderr io.Writer) error {
	if !strict {
		return nil
	}

	rt := ui.NewRuntime(stdout, stderr)
	done := rt.BeginProgress("perform strict integrity checks")
	defer done()

	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return fmt.Errorf("load default pack registry: %w", err)
	}
	if err := reg.ValidateStrict(ctlbuiltin.EmbeddedFS()); err != nil {
		return ui.WithNextCommand(err, "stave packs list")
	}
	return nil
}

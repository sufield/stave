package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/cmdutil/runid"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// runApply is the single dispatch function called by the thin RunE wrapper.
// All CLI state has already been extracted into cs. Context flows as the
// first parameter per Go convention.
func runApply(ctx context.Context, p *compose.Provider, opts *ApplyOptions, cs cobraState) error {
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
		dryCfg, dryErr := opts.ResolveDryRun(cs)
		if dryErr != nil {
			return fmt.Errorf("resolve dry-run config: %w", dryErr)
		}
		return runDryRun(ctx, p, dryCfg)
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
		runner := NewRunner(
			p.NewCELEvaluator,
			func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
				return compose.LoadControls(ctx, p, dir)
			},
			p.NewFindingWriter,
			cfg.profileClock,
			rt,
		)
		return runner.Run(ctx, *cfg.Profile)
	}

	sio, err := opts.ResolveStandardIO(cs)
	if err != nil {
		return fmt.Errorf("resolve output config: %w", err)
	}
	return runStandardApply(ctx, cs.Logger, p, opts, *cfg.Params, sio, cfg)
}

// evalContext groups the parameters needed by the evaluation pipeline.
type evalContext struct {
	Provider          *compose.Provider
	Opts              *ApplyOptions
	Params            applyParams
	IO                standardIO
	Plan              *appeval.EvaluationPlan
	Runtime           *ui.Runtime
	Logger            *slog.Logger
	ProjectConfig     *appconfig.ProjectConfig
	ProjectConfigPath string
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(ctx context.Context, logger *slog.Logger, p *compose.Provider, opts *ApplyOptions, params applyParams, sio standardIO, cfg RunConfig) error {
	evalInput, err := opts.buildEvaluatorInput(cfg.ControlsDir, cfg.ObservationsDir, cfg.projectConfigPath)
	if err != nil {
		return decorateError(fmt.Errorf("build evaluator input: %w", err))
	}
	plan, err := appeval.NewPlan(evalInput)
	if err != nil {
		return decorateError(fmt.Errorf("resolve evaluation plan: %w", err))
	}

	if plan != nil {
		logger = runid.SetupLoggingWithRunID(logger, plan.ObservationsHash.String(), plan.ControlsHash.String())
	}

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	ec := evalContext{
		Provider:          p,
		Opts:              opts,
		Params:            params,
		IO:                sio,
		Plan:              plan,
		Runtime:           rt,
		Logger:            logger,
		ProjectConfig:     cfg.projectConfig,
		ProjectConfigPath: cfg.projectConfigPath,
	}

	results, err := executeEvaluation(ctx, ec)
	if err != nil {
		return decorateError(err)
	}

	rep := &Reporter{Stdout: sio.Stdout, Stderr: sio.Stderr, Runtime: rt, Quiet: sio.Quiet}
	return rep.ReportApply(results, evaluation.ResponsePolicy{})
}

// executeEvaluation builds dependencies, runs the evaluation, and writes output.
func executeEvaluation(ctx context.Context, ec evalContext) (EvaluateResult, error) {
	progress := ec.Runtime.BeginCountedProgress("apply controls against observations")
	defer progress.Done()

	builder := NewBuilder(ec.Logger, ec.Opts, ec.Params, ec.IO)
	builder.NewFindingWriter = ec.Provider.NewFindingWriter
	builder.NewCtlRepo = ec.Provider.NewControlRepo
	builder.NewStdinObsRepo = ec.Provider.NewStdinObsRepo
	builder.ProjectConfig = ec.ProjectConfig
	builder.ProjectConfigPath = ec.ProjectConfigPath
	builder.OnObsProgress = progress.Update

	deps, err := builder.Build(ctx, ec.Plan)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("build evaluation dependencies: %w", err)
	}
	defer deps.Close()

	result, status, err := deps.Runner.ExecuteAndReturn(ctx, deps.Config)
	if err != nil {
		return EvaluateResult{}, fmt.Errorf("execute evaluation: %w", err)
	}

	if err := appeval.RunOutputPipeline(ctx, deps.Config.Output, result, deps.Runner.Marshaler, deps.Runner.EnrichFn, ec.Logger); err != nil {
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

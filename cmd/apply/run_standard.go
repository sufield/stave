package apply

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/runid"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
)

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
	pc, pcErr := resolveProjectContext()
	if pcErr != nil {
		return decorateError(pcErr)
	}
	evalInput := buildEvaluatorInput(opts, pc, cfg.ControlsDir, cfg.ObservationsDir, cfg.projectConfigPath)
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

package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/runid"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/staleness"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
)

// evalContext groups the parameters needed by the evaluation pipeline.
type evalContext struct {
	NewFindingWriter  compose.FindingWriterFactory
	NewCtlRepo        compose.CtlRepoFactory
	NewStdinObsRepo   func(io.Reader) (appcontracts.ObservationRepository, error)
	Opts              *Options
	Params            applyParams
	IO                StandardIO
	Plan              *appeval.EvaluationPlan
	Runtime           *ui.Runtime
	Logger            *slog.Logger
	ProjectConfig     *appconfig.WorkspacePolicy
	ProjectConfigPath string
}

// runStandardApply executes the standard plan → evaluate → output pipeline.
func runStandardApply(ctx context.Context, logger *slog.Logger, deps Deps, opts *Options, params applyParams, sio StandardIO, cfg RunConfig) error {
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
		NewFindingWriter:  deps.NewFindingWriter,
		NewCtlRepo:        deps.NewCtlRepo,
		NewStdinObsRepo:   deps.NewStdinObsRepo,
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

	// Staleness check: --assert-recent.
	if opts.AssertRecent != "" {
		threshold, parseErr := time.ParseDuration(opts.AssertRecent)
		if parseErr != nil {
			return &ui.UserError{Err: fmt.Errorf("parse --assert-recent: %w", parseErr)}
		}
		now := params.clock.Now()
		snapshots, snapErr := compose.LoadSnapshotsFrom(ctx, deps.NewObsRepo, cfg.ObservationsDir)
		if snapErr != nil {
			return fmt.Errorf("load snapshots for staleness check: %w", snapErr)
		}
		result := staleness.Check(snapshots, threshold, now)
		if result.Stale {
			return &ui.UserError{Err: fmt.Errorf("%s", result.Message)}
		}
	}

	// Signal-filtered output: --new-only or --new-since.
	if opts.NewOnly || opts.NewSince != "" {
		return runNewOnlyOutput(ctx, sio.Stdout, sio.Stderr, opts, results)
	}

	rep := &Reporter{Stdout: sio.Stdout, Stderr: sio.Stderr, Runtime: rt, Quiet: sio.Quiet}
	if err := rep.ReportApply(results, evaluation.EnforcementPolicy{}); err != nil {
		return err
	}

	// SLA policy exit code: check after normal evaluation reporting.
	return checkSLAPolicy(sio.Stderr, opts.SLAPolicy, results, sio.Quiet)
}

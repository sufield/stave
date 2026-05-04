package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/runid"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
)

// evalContext groups the parameters needed by the evaluation pipeline.
type evalContext struct {
	NewFindingWriter  compose.FindingWriterFactory
	NewCtlRepo        compose.CtlRepoFactory
	NewStdinObsRepo   func(io.Reader) (appcontracts.ObservationRepository, error)
	NewCELEvaluator   compose.CELEvaluatorFactory
	NewChainLoader    compose.ChainLoaderFactory
	NewSLALoader      compose.SLALoaderFactory
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
	if plan == nil {
		// NewPlan's contract is "(plan, nil) on success, (nil, err)
		// on failure". A (nil, nil) result here indicates a contract
		// violation by NewPlan, not normal operation — fail loud
		// rather than carry a nil plan into the run-id wiring (which
		// would nil-deref ObservationsHash) or executeEvaluation
		// (which dereferences plan throughout).
		return decorateError(errors.New("resolve evaluation plan: NewPlan returned nil without error"))
	}

	logger = runid.SetupLoggingWithRunID(logger, plan.ObservationsHash.String(), plan.ControlsHash.String())

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	ec := evalContext{
		NewFindingWriter:  deps.NewFindingWriter,
		NewCtlRepo:        deps.NewCtlRepo,
		NewStdinObsRepo:   deps.NewStdinObsRepo,
		NewCELEvaluator:   deps.NewCELEvaluator,
		NewChainLoader:    deps.NewChainLoader,
		NewSLALoader:      deps.NewSLALoader,
		Opts:              opts,
		Params:            params,
		IO:                sio,
		Plan:              plan,
		Runtime:           rt,
		Logger:            logger,
		ProjectConfig:     cfg.projectConfig,
		ProjectConfigPath: cfg.projectConfigPath,
	}

	// Staleness check: --assert-recent. Run BEFORE evaluation so a
	// stale-snapshot run fails fast instead of paying the full
	// evaluation cost only to be rejected. The decision-and-evaluate
	// pair lives on Options.CheckStaleness; we only load snapshots
	// when the flag is set so the cost is paid lazily.
	if opts.HasStalenessCheck() {
		snapshots, snapErr := compose.LoadSnapshotsFrom(ctx, deps.NewObsRepo, cfg.ObservationsDir)
		if snapErr != nil {
			return fmt.Errorf("load snapshots for staleness check: %w", snapErr)
		}
		if staleErr := opts.CheckStaleness(snapshots, params.clock.Now()); staleErr != nil {
			return staleErr
		}
	}

	results, err := executeEvaluation(ctx, ec)
	if err != nil {
		return decorateError(err)
	}

	// Signal-filtered output: --new-only or --new-since.
	// The signal view replaces the standard reporter's user-facing
	// summary, but the gating semantics — exit non-zero on
	// violations / SLA breach — must still apply, otherwise CI runs
	// with --new-only would pass on every active finding.
	if opts.IsNewOnlyMode() {
		if err := runNewOnlyOutput(ctx, sio.Stdout, sio.Stderr, opts, results); err != nil {
			return err
		}
		// Quiet flows from the user's --quiet flag (sio.Quiet) so
		// new-only mode respects the same verbosity contract as
		// every other apply path. The earlier hardcoded Quiet:
		// true ignored the user's choice and silenced gate
		// reporting even when -v was set.
		gate := NewReporter(sio, rt)
		if err := gate.ReportApply(results, evaluation.EnforcementPolicy{}); err != nil {
			return err
		}
		return gate.CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), results)
	}

	rep := NewReporter(sio, rt)
	if err := rep.ReportApply(results, evaluation.EnforcementPolicy{}); err != nil {
		return err
	}

	// SLA policy exit code: check after normal evaluation reporting.
	return rep.CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), results)
}

package diagnose

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	apptrace "github.com/sufield/stave/internal/app/trace"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

// Config holds the inputs for the diagnostic engine.
type Config struct {
	ControlsDir        string
	UseBuiltinControls bool
	ObservationsDir    string
	PreviousOutput     string
	MaxUnsafeDuration  time.Duration
	Format             appcontracts.OutputFormat
	Quiet              bool
	Cases              []string
	SignalContains     string
	Template           string

	// Detail Mode — used by `diagnose finding` subcommand.
	ControlID string
	AssetID   string

	// IO streams
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// Dependencies resolved by the CLI layer.
	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
}

// Runner orchestrates the diagnostic analysis.
type Runner struct {
	ObsRepo appcontracts.ObservationRepository
	CtlRepo appcontracts.ControlRepository
	Clock   ports.Clock
}

// NewRunner initializes a runner with pre-built dependencies.
func NewRunner(obsRepo appcontracts.ObservationRepository, ctlRepo appcontracts.ControlRepository, clock ports.Clock) *Runner {
	return &Runner{
		ObsRepo: obsRepo,
		CtlRepo: ctlRepo,
		Clock:   clock,
	}
}

// Run executes the standard diagnostic workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	// Disclosed fallback: no --controls and no controls/ dir → embedded catalog.
	if cfg.UseBuiltinControls && !cfg.Quiet && cfg.Stderr != nil {
		fmt.Fprintf(cfg.Stderr, "note: no --controls given and no controls/ directory found — "+
			"diagnosing against the built-in control catalog. Pass --controls <dir> to use your own.\n")
	}

	diagnoseRun, err := r.newDiagnosticEngine()
	if err != nil {
		return err
	}

	baseCfg, err := r.buildAuditRequest(cfg, cfg.MaxUnsafeDuration)
	if err != nil {
		return err
	}
	report, err := diagnoseRun.Analyze(ctx, baseCfg)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	if cfg.Sanitizer != nil && report != nil {
		report = appdiagnose.SanitizeDiagnosisReport(cfg.Sanitizer, report)
	}
	report = appdiagnose.Filter{
		Cases:          cfg.Cases,
		SignalContains: cfg.SignalContains,
	}.Apply(report)
	// Guard before passing to the presenter: Filter.Apply may
	// return nil when every issue is filtered out (or the input
	// was nil to begin with), and RenderReport / report.Issues
	// would otherwise nil-panic. Mirrors the sanitizer guard
	// above. Nil here means "nothing to report" — exit 0.
	if report == nil {
		return nil
	}

	p := r.newPresenter(cfg)
	if err := p.RenderReport(report); err != nil {
		return err
	}
	if len(report.Issues) > 0 {
		return ui.ErrDiagnosticsFound
	}
	return nil
}

func (r *Runner) runDetailMode(ctx context.Context, cfg Config) error {
	diagnoseRun, err := r.newDiagnosticEngine()
	if err != nil {
		return err
	}

	baseCfg, err := r.buildAuditRequest(cfg, cfg.MaxUnsafeDuration)
	if err != nil {
		return err
	}
	targetCtlID, err := kernel.NewControlID(cfg.ControlID)
	if err != nil {
		return fmt.Errorf("invalid control ID %q: %w", cfg.ControlID, err)
	}

	detail, err := diagnoseRun.InspectViolation(ctx, appdiagnose.InspectionRequest{
		AuditReq:     baseCfg,
		TargetPolicy: targetCtlID,
		TargetAsset:  asset.ID(cfg.AssetID),
		TraceBuilder: &apptrace.Builder{Tracer: cel.Tracer{}},
		IDGen:        crypto.NewHasher(),
	})

	if err != nil {
		return fmt.Errorf("inspect violation: %w", err)
	}

	p := r.newPresenter(cfg)
	if err := p.RenderDetail(detail); err != nil {
		return err
	}
	// runDetailMode only runs after InspectViolation has confirmed
	// a violation (otherwise the upstream returns an error), so the
	// detail view is always rendering a known violation — emit the
	// gating exit code unless the operator asked for JSON, where
	// the document itself carries the violation signal.
	if !cfg.Format.IsJSON() {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) newDiagnosticEngine() (*appdiagnose.DiagnosticEngine, error) {
	engine, err := appdiagnose.NewEngine(r.ObsRepo, r.CtlRepo)
	if err != nil {
		return nil, fmt.Errorf("create diagnostic engine: %w", err)
	}
	// Composition root wires the built-in catalog loader so the app
	// layer can fall back to the embedded catalog when --controls is
	// absent without importing adapters/* itself.
	engine.BuiltinCatalog = compose.BuiltinControlCatalog
	return engine, nil
}

func (r *Runner) buildAuditRequest(cfg Config, maxDuration time.Duration) (appdiagnose.AuditRequest, error) {
	req := appdiagnose.AuditRequest{
		PolicySource:      cfg.ControlsDir,
		ObservationSource: cfg.ObservationsDir,
		SLAThreshold:      maxDuration,
		Clock:             r.Clock,
		PredicateParser:   ctlyaml.ParsePredicate,
	}

	loader := &evaljson.Loader{}
	switch {
	case cfg.PreviousOutput == "-":
		result, err := loader.LoadFromReader(cfg.Stdin, "stdin")
		if err != nil {
			return appdiagnose.AuditRequest{}, fmt.Errorf("load evaluation from stdin: %w", err)
		}
		req.BaselineReport = result
	case cfg.PreviousOutput != "":
		result, err := loader.LoadFromFile(cfg.PreviousOutput)
		if err != nil {
			return appdiagnose.AuditRequest{}, fmt.Errorf("load evaluation from %q: %w", cfg.PreviousOutput, err)
		}
		req.BaselineReport = result
	}
	return req, nil
}

func (r *Runner) newPresenter(cfg Config) *Presenter {
	return &Presenter{
		W:        compose.ResolveStdout(cfg.Stdout, cfg.Quiet, cfg.Format),
		Format:   cfg.Format,
		Template: cfg.Template,
	}
}

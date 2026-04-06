package diagnose

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
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
	ControlsDir       string
	ObservationsDir   string
	PreviousOutput    string
	MaxUnsafeDuration time.Duration
	Format            appcontracts.OutputFormat
	Quiet             bool
	Cases             []string
	SignalContains    string
	Template          string

	// Detail Mode (single-finding deep dive)
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

// IsDetailMode returns true if both IDs are provided for a deep-dive analysis.
func (c Config) IsDetailMode() bool {
	return c.ControlID != "" && c.AssetID != ""
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

// Run executes the diagnostic workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := r.validate(cfg); err != nil {
		return err
	}
	if cfg.IsDetailMode() {
		return r.runDetailMode(ctx, cfg)
	}
	return r.runStandardDiagnosis(ctx, cfg)
}

func (r *Runner) validate(cfg Config) error {
	if (cfg.ControlID != "" && cfg.AssetID == "") || (cfg.ControlID == "" && cfg.AssetID != "") {
		return &ui.UserError{Err: fmt.Errorf("detail mode requires both --control-id AND --asset-id")}
	}
	return nil
}

func (r *Runner) runStandardDiagnosis(ctx context.Context, cfg Config) error {
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
		return err
	}

	if cfg.Sanitizer != nil && report != nil {
		report = appdiagnose.SanitizeDiagnosisReport(cfg.Sanitizer, report)
	}
	report = appdiagnose.Filter{
		Cases:          cfg.Cases,
		SignalContains: cfg.SignalContains,
	}.Apply(report)

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
	detail, err := diagnoseRun.InspectViolation(ctx, appdiagnose.InspectionRequest{
		AuditReq:     baseCfg,
		TargetPolicy: kernel.ControlID(cfg.ControlID),
		TargetAsset:  asset.ID(cfg.AssetID),
		TraceBuilder: &apptrace.Builder{},
		IDGen:        crypto.NewHasher(),
	})

	if err != nil {
		return err
	}

	p := r.newPresenter(cfg)
	if err := p.RenderDetail(detail); err != nil {
		return err
	}
	if !cfg.Format.IsJSON() {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) newDiagnosticEngine() (*appdiagnose.DiagnosticEngine, error) {
	return appdiagnose.NewEngine(r.ObsRepo, r.CtlRepo)
}

func (r *Runner) buildAuditRequest(cfg Config, maxDuration time.Duration) (appdiagnose.AuditRequest, error) {
	req := appdiagnose.AuditRequest{
		PolicySource:    cfg.ControlsDir,
		InventorySource: cfg.ObservationsDir,
		SLAThreshold:    maxDuration,
		Clock:           r.Clock,
		PredicateParser: ctlyaml.ParsePredicate,
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

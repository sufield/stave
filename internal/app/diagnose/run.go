package diagnose

import (
	"context"
	"fmt"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// Config holds configuration for the diagnose use case.
type Config struct {
	ControlsDir     string
	ObservationsDir string
	OutputFile      string    // Optional: path to existing apply output JSON.
	OutputReader    io.Reader // Optional: reader for apply output JSON (e.g. stdin).
	MaxUnsafe       time.Duration
	Clock           ports.Clock
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

// Run executes the diagnose use case.
type Run struct {
	ObservationRepo appcontracts.ObservationRepository
	ControlRepo     appcontracts.ControlRepository
	ResultLoader    appcontracts.ResultLoader
}

type artifacts struct {
	controls  []policy.ControlDefinition
	snapshots []asset.Snapshot
}

// NewRun creates a new diagnose run instance.
func NewRun(
	obsRepo appcontracts.ObservationRepository,
	ctlRepo appcontracts.ControlRepository,
	resultLoader appcontracts.ResultLoader,
) (*Run, error) {
	if obsRepo == nil {
		return nil, fmt.Errorf("NewRun requires non-nil ObservationRepository")
	}
	if ctlRepo == nil {
		return nil, fmt.Errorf("NewRun requires non-nil ControlRepository")
	}
	return &Run{
		ObservationRepo: obsRepo,
		ControlRepo:     ctlRepo,
		ResultLoader:    resultLoader,
	}, nil
}

// Execute runs diagnostics and returns the report.
func (d *Run) Execute(ctx context.Context, cfg Config) (*diagnosis.Report, error) {
	loaded, err := d.loadArtifacts(ctx, cfg.ControlsDir, cfg.ObservationsDir)
	if err != nil {
		return nil, fmt.Errorf("load artifacts: %w", err)
	}

	result, err := d.resolveResult(cfg, loaded)
	if err != nil {
		return nil, fmt.Errorf("resolve result: %w", err)
	}

	input := diagnosis.NewInput(
		loaded.snapshots,
		loaded.controls,
		result.Findings,
		result,
		cfg.MaxUnsafe,
		cfg.Clock.Now(),
	)

	report := diagnosis.Explain(input)
	return &report, nil
}

// FindingDetailConfig holds configuration for the finding detail use case.
type FindingDetailConfig struct {
	DiagnoseConfig Config
	ControlID      kernel.ControlID
	AssetID        asset.ID
	TraceBuilder   evaluation.FindingTraceBuilder
}

// ExecuteFindingDetail loads data and builds a detailed diagnosis for a single finding.
func (d *Run) ExecuteFindingDetail(ctx context.Context, cfg FindingDetailConfig) (*evaluation.FindingDetail, error) {
	loaded, err := d.loadArtifacts(ctx, cfg.DiagnoseConfig.ControlsDir, cfg.DiagnoseConfig.ObservationsDir)
	if err != nil {
		return nil, fmt.Errorf("load artifacts: %w", err)
	}

	result, err := d.resolveResult(cfg.DiagnoseConfig, loaded)
	if err != nil {
		return nil, fmt.Errorf("resolve result: %w", err)
	}

	return service.BuildFindingDetail(service.FindingDetailInput{
		ControlID:    cfg.ControlID,
		AssetID:      cfg.AssetID,
		Controls:     loaded.controls,
		Snapshots:    loaded.snapshots,
		Result:       result,
		TraceBuilder: cfg.TraceBuilder,
	})
}

func (d *Run) loadArtifacts(
	ctx context.Context,
	controlsDir string,
	observationsDir string,
) (artifacts, error) {
	controls, err := appcontracts.LoadControls(ctx, d.ControlRepo, controlsDir)
	if err != nil {
		return artifacts{}, fmt.Errorf("load controls: %w", err)
	}

	obsResult, err := appcontracts.LoadSnapshots(ctx, d.ObservationRepo, observationsDir)
	if err != nil {
		return artifacts{}, fmt.Errorf("load observations: %w", err)
	}
	snapshots := obsResult.Snapshots

	return artifacts{
		controls:  controls,
		snapshots: snapshots,
	}, nil
}

func (d *Run) resolveResult(
	cfg Config,
	artifacts artifacts,
) (*evaluation.Result, error) {
	if cfg.OutputReader != nil {
		if d.ResultLoader == nil {
			return nil, fmt.Errorf("evaluation result repository is not configured: cannot load from reader")
		}
		return d.ResultLoader.LoadFromReader(cfg.OutputReader, "stdin")
	}
	if cfg.OutputFile != "" {
		if d.ResultLoader == nil {
			return nil, fmt.Errorf("evaluation result repository is not configured: cannot load from file %q", cfg.OutputFile)
		}
		return d.ResultLoader.LoadFromFile(cfg.OutputFile)
	}

	result, err := service.Evaluate(service.EvaluateInput{
		Controls:        artifacts.controls,
		Snapshots:       artifacts.snapshots,
		MaxUnsafe:       cfg.MaxUnsafe,
		Clock:           cfg.Clock,
		PredicateParser: cfg.PredicateParser,
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

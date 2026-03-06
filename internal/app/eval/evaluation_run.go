package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// LoadConfig holds configuration for loading evaluation artifacts from the filesystem.
type LoadConfig struct {
	ControlsDir       string
	ObservationsDir   string
	AllowUnknownInput bool
	Stderr            io.Writer
	PreloadedControls []policy.ControlDefinition
}

// EvaluateConfig holds configuration for the evaluate use case.
type EvaluateConfig struct {
	LoadConfig
	MaxUnsafe         time.Duration
	Clock             ports.Clock
	Output            io.Writer
	ExemptionConfig   *policy.ExemptionConfig
	SuppressionConfig *policy.SuppressionConfig
	ToolVersion       string
	Metadata          evaluation.Metadata
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
}

// EvaluateRun executes the evaluation use case.
type EvaluateRun struct {
	ObservationRepo appcontracts.ObservationRepository
	ControlRepo     appcontracts.ControlRepository
	Marshaler       appcontracts.FindingMarshaler
	EnrichFn        appcontracts.EnrichFunc
	Logger          *slog.Logger
}

var _ EvaluateRunner = (*EvaluateRun)(nil)

// NewEvaluateRun creates an evaluate run with the explicit
// Enrich → Marshal → Write pipeline.
func NewEvaluateRun(
	obsRepo appcontracts.ObservationRepository,
	ctlRepo appcontracts.ControlRepository,
	marshaler appcontracts.FindingMarshaler,
	enrichFn appcontracts.EnrichFunc,
) *EvaluateRun {
	return &EvaluateRun{
		ObservationRepo: obsRepo,
		ControlRepo:     ctlRepo,
		Marshaler:       marshaler,
		EnrichFn:        enrichFn,
	}
}

// Execute runs the evaluation and returns the safety status.
func (e *EvaluateRun) Execute(ctx context.Context, cfg EvaluateConfig) (evaluation.SafetyStatus, error) {
	preflight := e.loadEvaluationArtifacts(ctx, cfg.LoadConfig)
	if preflight.HasErrors() {
		return "", preflight.FirstError()
	}
	controls := cfg.PreloadedControls
	if controls == nil {
		controls = preflight.Controls
	}
	snapshots := preflight.Snapshots

	result := service.Evaluate(service.EvaluateInput{
		Controls:          controls,
		Snapshots:         snapshots,
		MaxUnsafe:         cfg.MaxUnsafe,
		Clock:             cfg.Clock,
		ExemptionConfig:   cfg.ExemptionConfig,
		SuppressionConfig: cfg.SuppressionConfig,
		ToolVersion:       cfg.ToolVersion,
		InputHashes:       preflight.Hashes,
		PredicateParser:   cfg.PredicateParser,
		Metadata:          cfg.Metadata,
	})

	// Write output: use explicit pipeline when available, else legacy writer.
	if err := e.writeOutput(ctx, cfg.Output, result); err != nil {
		return "", fmt.Errorf("failed to write findings: %w", err)
	}

	return result.SafetyStatus(), nil
}

// writeOutput writes findings using the Enrich → Marshal → Write pipeline.
func (e *EvaluateRun) writeOutput(ctx context.Context, out io.Writer, result evaluation.Result) error {
	wrap := func(name string, s Step) Step {
		s = WithRecovery(name, s)
		s = WithLogging(e.Logger, name, s)
		return s
	}
	return NewPipeline(ctx, &PipelineData{Result: result, Output: out}).
		Then(wrap("enrich", EnrichStep(e.EnrichFn))).
		Then(wrap("marshal", MarshalStep(e.Marshaler))).
		Then(wrap("write", WriteStep())).
		Error()
}

func (e *EvaluateRun) loadEvaluationArtifacts(ctx context.Context, cfg LoadConfig) IntentEvaluationResult {
	intent := NewIntentEvaluation(e.ObservationRepo, e.ControlRepo)
	return intent.LoadArtifacts(ctx, IntentEvaluationConfig{
		ControlsDir:       cfg.ControlsDir,
		ObservationsDir:   cfg.ObservationsDir,
		RequireControls:   cfg.PreloadedControls == nil,
		AllowUnknownInput: cfg.AllowUnknownInput,
		Stderr:            cfg.Stderr,
	})
}

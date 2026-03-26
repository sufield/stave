package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
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
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	Output            io.Writer
	ExemptionConfig   *policy.ExemptionConfig
	ExceptionConfig   *policy.ExceptionConfig
	StaveVersion      string
	Metadata          evaluation.Metadata
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	CELEvaluator      policy.PredicateEval
}

// EvaluateRun executes the evaluation use case.
type EvaluateRun struct {
	ObservationRepo appcontracts.ObservationRepository
	ControlRepo     appcontracts.ControlRepository
	Marshaler       appcontracts.FindingMarshaler
	EnrichFn        appcontracts.EnrichFunc
	Logger          *slog.Logger
}

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

// ExecuteAndReturn runs the evaluation and returns the Result alongside SafetyStatus
// without writing output. The caller is responsible for output rendering.
func (e *EvaluateRun) ExecuteAndReturn(ctx context.Context, cfg EvaluateConfig) (evaluation.Result, evaluation.SafetyStatus, error) {
	preflight := e.loadEvaluationArtifacts(ctx, cfg.LoadConfig)
	if preflight.HasErrors() {
		return evaluation.Result{}, "", preflight.FirstError()
	}
	controls := cfg.PreloadedControls
	if controls == nil {
		controls = preflight.Controls
	}
	snapshots := preflight.Snapshots

	result, err := appworkflow.Evaluate(appworkflow.EvaluateInput{
		Controls:          controls,
		Snapshots:         snapshots,
		MaxUnsafeDuration: cfg.MaxUnsafeDuration,
		Clock:             cfg.Clock,
		Hasher:            cfg.Hasher,
		ExemptionConfig:   cfg.ExemptionConfig,
		ExceptionConfig:   cfg.ExceptionConfig,
		StaveVersion:      cfg.StaveVersion,
		InputHashes:       preflight.Hashes,
		PredicateParser:   cfg.PredicateParser,
		CELEvaluator:      cfg.CELEvaluator,
		Metadata:          cfg.Metadata,
	})
	if err != nil {
		return evaluation.Result{}, "", fmt.Errorf("evaluation failed: %w", err)
	}

	return result, result.SafetyStatus, nil
}

func (e *EvaluateRun) loadEvaluationArtifacts(ctx context.Context, cfg LoadConfig) IntentEvaluationResult {
	intent := NewIntentEvaluation(e.ObservationRepo, e.ControlRepo)
	return intent.LoadArtifacts(ctx, IntentEvaluationConfig{
		ControlsDir:       cfg.ControlsDir,
		ObservationsDir:   cfg.ObservationsDir,
		RequireControls:   cfg.PreloadedControls == nil,
		SkipControlsLoad:  cfg.PreloadedControls != nil,
		AllowUnknownInput: cfg.AllowUnknownInput,
		Stderr:            cfg.Stderr,
	})
}

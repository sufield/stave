package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
)

// BuildDependenciesInput configures evaluator dependency assembly.
// Callers must provide all pre-built dependencies; the evaluator
// package does not create concrete adapters.
type BuildDependenciesInput struct {
	Plan EvaluationPlan

	FindingMarshaler  appcontracts.FindingMarshaler
	EnrichFn          appcontracts.EnrichFunc
	ObservationLoader appcontracts.ObservationRepository
	ControlLoader     appcontracts.ControlRepository

	MaxUnsafe         time.Duration
	Clock             ports.Clock
	Output            io.Writer
	Stderr            io.Writer
	AllowUnknownInput bool
	ToolVersion       string

	ExemptionConfig *policy.ExemptionConfig

	ProjectConfig   ProjectConfigInput
	GitMetadata     *evaluation.GitInfo
	Filters         ControlFilter
	ControlsDir     string
	PredicateParser func(any) (*policy.UnsafePredicate, error)
}

// BuildDependenciesOutput is the assembled runner + config pair.
type BuildDependenciesOutput struct {
	Runner EvaluateRunner
	Config EvaluateConfig
}

// BuildDependencies assembles the evaluate runner and config from
// pre-built dependencies. All loaders and writers must be created
// by the caller before invoking this function.
func BuildDependencies(in BuildDependenciesInput) (BuildDependenciesOutput, error) {
	if err := validateBuildDependenciesInput(in); err != nil {
		return BuildDependenciesOutput{}, err
	}

	resolved, err := ResolveProjectConfig(context.Background(), in.ProjectConfig)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	preloaded, err := resolvePreloadedControls(in, resolved)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	output, stderr := resolveOutputWriters(in.Output, in.Stderr)

	opts := []Option{
		WithRuntime(output, stderr, in.Clock, in.ToolVersion),
		WithMaxUnsafe(in.MaxUnsafe),
		WithAllowUnknownInput(in.AllowUnknownInput),
		WithExemptionConfig(in.ExemptionConfig),
		WithSuppressionConfig(resolved.SuppressionConfig),
		WithPreloadedControls(preloaded),
		WithGitMetadata(in.GitMetadata),
		WithPredicateParser(in.PredicateParser),
	}
	if resolved.ControlSource.Source != "" {
		opts = append(opts, WithControlSource(resolved.ControlSource))
	}

	cfg := NewConfig(in.Plan, opts...)

	runner := NewEvaluateRun(in.ObservationLoader, in.ControlLoader, in.FindingMarshaler, in.EnrichFn)
	runner.Logger = slog.Default()

	return BuildDependenciesOutput{
		Runner: runner,
		Config: cfg,
	}, nil
}

func resolvePreloadedControls(in BuildDependenciesInput, resolved ResolvedProjectConfig) ([]policy.ControlDefinition, error) {
	preloaded := resolved.PreloadedControls
	if !in.Filters.Enabled() {
		return preloaded, nil
	}
	if len(preloaded) == 0 {
		dir := strings.TrimSpace(in.ControlsDir)
		if dir == "" {
			dir = in.Plan.ControlsPath
		}
		loaded, err := in.ControlLoader.LoadControls(context.Background(), dir)
		if err != nil {
			return nil, fmt.Errorf("load controls for filtering: %w", err)
		}
		preloaded = loaded
	}
	return FilterControls(preloaded, in.Filters)
}

func resolveOutputWriters(output, stderr io.Writer) (io.Writer, io.Writer) {
	if output == nil {
		output = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return output, stderr
}

func validateBuildDependenciesInput(in BuildDependenciesInput) error {
	if in.Plan.ControlsPath == "" {
		return fmt.Errorf("evaluation plan is required")
	}
	if in.ControlLoader == nil {
		return fmt.Errorf("control loader is not configured")
	}
	if in.ObservationLoader == nil {
		return fmt.Errorf("observation loader is not configured")
	}
	if in.FindingMarshaler == nil {
		return fmt.Errorf("finding marshaler is not configured")
	}
	if in.EnrichFn == nil {
		return fmt.Errorf("enrich function is not configured")
	}
	return nil
}

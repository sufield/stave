package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
)

// Adapters holds the injected port implementations for evaluation.
type Adapters struct {
	FindingMarshaler  appcontracts.FindingMarshaler
	EnrichFn          appcontracts.EnrichFunc
	ObservationLoader appcontracts.ObservationRepository
	ControlLoader     appcontracts.ControlRepository
}

// RuntimeConfig holds evaluation parameters that control behavior.
type RuntimeConfig struct {
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	StaveVersion      string
	AllowUnknownInput bool
	ExemptionConfig   *policy.ExemptionConfig
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	CELEvaluator      policy.PredicateEval
}

// OutputWriters holds the destination writers for evaluation output.
type OutputWriters struct {
	Stdout io.Writer
	Stderr io.Writer
}

// ProjectScope holds project configuration and control filtering inputs.
type ProjectScope struct {
	Config      ProjectConfigInput
	GitMetadata *evaluation.GitInfo
	Filters     ControlFilter
	ControlsDir string
}

// BuildDependenciesInput configures evaluator dependency assembly.
// Fields are grouped by lifecycle phase: Adapters for injected ports,
// Runtime for evaluation parameters, Writers for output destinations,
// and Project for configuration resolution.
type BuildDependenciesInput struct {
	Plan    EvaluationPlan
	Context context.Context
	Logger  *slog.Logger

	Adapters Adapters
	Runtime  RuntimeConfig
	Writers  OutputWriters
	Project  ProjectScope
}

// BuildDependenciesOutput is the assembled runner + config pair.
type BuildDependenciesOutput struct {
	Runner *EvaluateRun
	Config EvaluateConfig
}

// BuildDependencies assembles the evaluate runner and config from
// pre-built dependencies. All loaders and writers must be created
// by the caller before invoking this function.
func BuildDependencies(in BuildDependenciesInput) (BuildDependenciesOutput, error) {
	if err := validateBuildDependenciesInput(in); err != nil {
		return BuildDependenciesOutput{}, err
	}

	ctx := in.Context

	resolved, err := ResolveProjectConfig(in.Project.Config)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	preloaded, err := resolvePreloadedControls(ctx, in, resolved)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	output, stderr := resolveOutputWriters(in.Writers.Stdout, in.Writers.Stderr)

	opts := []Option{
		WithRuntime(output, stderr, in.Runtime.Clock, in.Runtime.StaveVersion),
		WithMaxUnsafeDuration(in.Runtime.MaxUnsafeDuration),
		WithHasher(in.Runtime.Hasher),
		WithAllowUnknownInput(in.Runtime.AllowUnknownInput),
		WithExemptionConfig(in.Runtime.ExemptionConfig),
		WithExceptionConfig(resolved.ExceptionConfig),
		WithPreloadedControls(preloaded),
		WithGitMetadata(in.Project.GitMetadata),
		WithPredicateParser(in.Runtime.PredicateParser),
		WithCELEvaluator(in.Runtime.CELEvaluator),
	}
	if resolved.ControlSource.Source != "" {
		opts = append(opts, WithControlSource(resolved.ControlSource))
	}

	cfg := NewConfig(in.Plan, opts...)

	runner := NewEvaluateRun(in.Adapters.ObservationLoader, in.Adapters.ControlLoader, in.Adapters.FindingMarshaler, in.Adapters.EnrichFn)
	runner.Logger = in.Logger

	return BuildDependenciesOutput{
		Runner: runner,
		Config: cfg,
	}, nil
}

func resolvePreloadedControls(ctx context.Context, in BuildDependenciesInput, resolved ResolvedProjectConfig) ([]policy.ControlDefinition, error) {
	preloaded := resolved.PreloadedControls
	if !in.Project.Filters.Enabled() {
		return preloaded, nil
	}
	if len(preloaded) == 0 {
		dir := strings.TrimSpace(in.Project.ControlsDir)
		if dir == "" {
			dir = in.Plan.ControlsPath
		}
		loaded, err := in.Adapters.ControlLoader.LoadControls(ctx, dir)
		if err != nil {
			return nil, fmt.Errorf("load controls for filtering: %w", err)
		}
		preloaded = loaded
	}
	return FilterControls(preloaded, in.Project.Filters)
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
	if in.Adapters.ControlLoader == nil {
		return fmt.Errorf("control loader is not configured")
	}
	if in.Adapters.ObservationLoader == nil {
		return fmt.Errorf("observation loader is not configured")
	}
	if in.Adapters.FindingMarshaler == nil {
		return fmt.Errorf("finding marshaler is not configured")
	}
	if in.Adapters.EnrichFn == nil {
		return fmt.Errorf("enrich function is not configured")
	}
	return nil
}

// ApplyDeps holds wired dependencies for the apply workflow.
type ApplyDeps struct {
	Runner *EvaluateRun
	Config EvaluateConfig
}

// Close releases assets held by ApplyDeps.
func (d *ApplyDeps) Close() {}

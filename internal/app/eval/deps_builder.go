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
// Fields are grouped by lifecycle phase: Adapters for injected ports,
// Runtime for evaluation parameters, Writers for output destinations,
// and Project for configuration resolution.
type BuildDependenciesInput struct {
	Plan    EvaluationPlan
	Context context.Context

	Adapters Adapters
	Runtime  RuntimeConfig
	Writers  OutputWriters
	Project  ProjectScope
}

// Adapters holds the injected port implementations for evaluation.
type Adapters struct {
	FindingMarshaler  appcontracts.FindingMarshaler
	EnrichFn          appcontracts.EnrichFunc
	ObservationLoader appcontracts.ObservationRepository
	ControlLoader     appcontracts.ControlRepository
}

// RuntimeConfig holds evaluation parameters that control behavior.
type RuntimeConfig struct {
	MaxUnsafe         time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	ToolVersion       string
	AllowUnknownInput bool
	ExemptionConfig   *policy.ExemptionConfig
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
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

	ctx := in.Context
	if ctx == nil {
		ctx = context.Background()
	}

	resolved, err := ResolveProjectConfig(ctx, in.Project.Config)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	preloaded, err := resolvePreloadedControls(ctx, in, resolved)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	output, stderr := resolveOutputWriters(in.Writers.Stdout, in.Writers.Stderr)

	opts := []Option{
		WithRuntime(output, stderr, in.Runtime.Clock, in.Runtime.ToolVersion),
		WithMaxUnsafe(in.Runtime.MaxUnsafe),
		WithHasher(in.Runtime.Hasher),
		WithAllowUnknownInput(in.Runtime.AllowUnknownInput),
		WithExemptionConfig(in.Runtime.ExemptionConfig),
		WithSuppressionConfig(resolved.SuppressionConfig),
		WithPreloadedControls(preloaded),
		WithGitMetadata(in.Project.GitMetadata),
		WithPredicateParser(in.Runtime.PredicateParser),
	}
	if resolved.ControlSource.Source != "" {
		opts = append(opts, WithControlSource(resolved.ControlSource))
	}

	cfg := NewConfig(in.Plan, opts...)

	runner := NewEvaluateRun(in.Adapters.ObservationLoader, in.Adapters.ControlLoader, in.Adapters.FindingMarshaler, in.Adapters.EnrichFn)
	runner.Logger = slog.Default()

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

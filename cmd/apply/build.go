package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
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
	Config      appeval.ProjectConfigInput
	GitMetadata *evaluation.GitInfo
	Filters     appeval.ControlFilter
	ControlsDir string
}

// BuildDependenciesInput configures evaluator dependency assembly.
// Fields are grouped by lifecycle phase: Adapters for injected ports,
// Runtime for evaluation parameters, Writers for output destinations,
// and Project for configuration resolution.
type BuildDependenciesInput struct {
	Plan    appeval.EvaluationPlan
	Context context.Context

	Adapters Adapters
	Runtime  RuntimeConfig
	Writers  OutputWriters
	Project  ProjectScope
}

// BuildDependenciesOutput is the assembled runner + config pair.
type BuildDependenciesOutput struct {
	Runner *appeval.EvaluateRun
	Config appeval.EvaluateConfig
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

	resolved, err := appeval.ResolveProjectConfig(ctx, in.Project.Config)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	preloaded, err := resolvePreloadedControls(ctx, in, resolved)
	if err != nil {
		return BuildDependenciesOutput{}, err
	}

	output, stderr := resolveOutputWriters(in.Writers.Stdout, in.Writers.Stderr)

	opts := []appeval.Option{
		appeval.WithRuntime(output, stderr, in.Runtime.Clock, in.Runtime.ToolVersion),
		appeval.WithMaxUnsafe(in.Runtime.MaxUnsafe),
		appeval.WithHasher(in.Runtime.Hasher),
		appeval.WithAllowUnknownInput(in.Runtime.AllowUnknownInput),
		appeval.WithExemptionConfig(in.Runtime.ExemptionConfig),
		appeval.WithExceptionConfig(resolved.ExceptionConfig),
		appeval.WithPreloadedControls(preloaded),
		appeval.WithGitMetadata(in.Project.GitMetadata),
		appeval.WithPredicateParser(in.Runtime.PredicateParser),
	}
	if resolved.ControlSource.Source != "" {
		opts = append(opts, appeval.WithControlSource(resolved.ControlSource))
	}

	cfg := appeval.NewConfig(in.Plan, opts...)

	runner := appeval.NewEvaluateRun(in.Adapters.ObservationLoader, in.Adapters.ControlLoader, in.Adapters.FindingMarshaler, in.Adapters.EnrichFn)
	runner.Logger = slog.Default()

	return BuildDependenciesOutput{
		Runner: runner,
		Config: cfg,
	}, nil
}

func resolvePreloadedControls(ctx context.Context, in BuildDependenciesInput, resolved appeval.ResolvedProjectConfig) ([]policy.ControlDefinition, error) {
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
	return appeval.FilterControls(preloaded, in.Project.Filters)
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
	Runner *appeval.EvaluateRun
	Config appeval.EvaluateConfig
}

// Close releases assets held by ApplyDeps.
func (d *ApplyDeps) Close() {}

// ApplyBuilderInput holds all pre-resolved inputs needed to build apply
// dependencies. All cmd-layer resolution (provider calls, project config
// lookup, git status, exemption loading) must be done by the caller.
type ApplyBuilderInput struct {
	Ctx    context.Context
	Stdout io.Writer
	Stderr io.Writer

	Plan appeval.EvaluationPlan

	// Adapters (pre-built by caller)
	Marshaler appcontracts.FindingMarshaler
	ObsLoader appcontracts.ObservationRepository
	CtlLoader appcontracts.ControlRepository
	EnrichFn  appcontracts.EnrichFunc

	// Runtime parameters
	MaxUnsafe         time.Duration
	Clock             ports.Clock
	Hasher            ports.Digester
	AllowUnknownInput bool
	ExemptionConfig   *policy.ExemptionConfig
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	ToolVersion       string

	// Project scope
	ControlsDir    string
	ProjectConfig  appeval.ProjectConfigInput
	GitMetadata    *evaluation.GitInfo
	ControlFilters appeval.ControlFilter
}

// BuildApplyDeps assembles ApplyDeps from fully resolved inputs.
func BuildApplyDeps(in ApplyBuilderInput) (*ApplyDeps, error) {
	ctx := in.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	built, err := BuildDependencies(BuildDependenciesInput{
		Plan:    in.Plan,
		Context: ctx,
		Adapters: Adapters{
			FindingMarshaler:  in.Marshaler,
			EnrichFn:          in.EnrichFn,
			ObservationLoader: in.ObsLoader,
			ControlLoader:     in.CtlLoader,
		},
		Runtime: RuntimeConfig{
			MaxUnsafe:         in.MaxUnsafe,
			Clock:             in.Clock,
			Hasher:            in.Hasher,
			ToolVersion:       in.ToolVersion,
			AllowUnknownInput: in.AllowUnknownInput,
			ExemptionConfig:   in.ExemptionConfig,
			PredicateParser:   in.PredicateParser,
		},
		Writers: OutputWriters{
			Stdout: in.Stdout,
			Stderr: in.Stderr,
		},
		Project: ProjectScope{
			Config:      in.ProjectConfig,
			GitMetadata: in.GitMetadata,
			Filters:     in.ControlFilters,
			ControlsDir: in.ControlsDir,
		},
	})
	if err != nil {
		return nil, err
	}

	return &ApplyDeps{Runner: built.Runner, Config: built.Config}, nil
}

package eval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
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
	MaxUnsafeDuration    time.Duration
	Clock                ports.Clock
	Hasher               ports.Digester
	StaveVersion         string
	AllowUnknownInput    bool
	ExemptionConfig      *policy.ExemptionConfig
	AcknowledgmentConfig *policy.AcknowledgmentConfig
	PredicateParser      func(any) (*policy.UnsafePredicate, error)
	CELEvaluator         policy.PredicateEval
	Tracer               ports.Tracer
	ChainDefs            []policy.ChainDefinition
	SLAConfig            *evaluation.SLAConfig
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
	Plan   EvaluationPlan
	Logger *slog.Logger

	Adapters Adapters
	Runtime  RuntimeConfig
	Writers  OutputWriters
	Project  ProjectScope
}

// BuildDependenciesOutput is the assembled runner + config pair.
type BuildDependenciesOutput struct {
	Runner *AuditWorkflow
	Config AssessmentConfig
}

// BuildDependencies assembles the evaluate runner and config from
// pre-built dependencies. All loaders and writers must be created
// by the caller before invoking this function.
func BuildDependencies(ctx context.Context, in *BuildDependenciesInput) (BuildDependenciesOutput, error) {
	if err := validateBuildDependenciesInput(in); err != nil {
		return BuildDependenciesOutput{}, err
	}

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
		WithAcknowledgmentConfig(in.Runtime.AcknowledgmentConfig),
		WithPreloadedControls(preloaded),
		WithGitMetadata(in.Project.GitMetadata),
		WithPredicateParser(in.Runtime.PredicateParser),
		WithCELEvaluator(in.Runtime.CELEvaluator),
		WithTracer(in.Runtime.Tracer),
		WithChainDefs(filterResolvedChains(in.Runtime.ChainDefs, preloaded, in.Logger)),
		WithSLAConfig(in.Runtime.SLAConfig),
	}
	if resolved.ControlSource.Source != "" {
		opts = append(opts, WithControlSource(resolved.ControlSource))
	}

	cfg := NewConfig(in.Plan, opts...)

	runner := NewAuditWorkflow(in.Adapters.ObservationLoader, in.Adapters.ControlLoader, in.Adapters.FindingMarshaler, in.Adapters.EnrichFn)
	runner.Logger = in.Logger

	return BuildDependenciesOutput{
		Runner: runner,
		Config: cfg,
	}, nil
}

func resolvePreloadedControls(ctx context.Context, in *BuildDependenciesInput, resolved ResolvedProjectConfig) ([]policy.ControlDefinition, error) {
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

// filterResolvedChains returns only chains whose controls are ALL
// present in the active control set. Chains referencing missing
// controls — e.g. excluded by profile filtering or authored with a
// typo — are dropped, with each drop logged as a warning so users
// get feedback instead of silent tolerance. The warning names the
// chain and every missing reference; a typo surfaces the same way
// a profile-filter drop does, letting the user distinguish by
// inspection.
func filterResolvedChains(chains []policy.ChainDefinition, controls []policy.ControlDefinition, logger *slog.Logger) []policy.ChainDefinition {
	if len(chains) == 0 {
		return nil
	}
	// When the active catalog isn't known at this layer (empty preloaded
	// set — the common case for `stave apply --controls <dir>` without
	// filter configuration), skip reference validation. The chain engine
	// operates against the fully-loaded catalog at runtime; chains whose
	// controls are genuinely missing silently fail to activate there.
	// Filtering against an empty proxy drops every chain and produces
	// adopter-facing drift between CLI and library paths. Typo detection
	// in the no-preload case is a separate concern — see
	// docs/design-notes for the follow-up proposal.
	if len(controls) == 0 {
		return chains
	}
	issues := policy.ValidateChainRefs(chains, controls)
	if len(issues) > 0 && logger != nil {
		for _, issue := range issues {
			missing := make([]string, len(issue.MissingControl))
			for i, id := range issue.MissingControl {
				missing[i] = string(id)
			}
			logger.Warn("chain dropped: references controls not in the active catalog",
				"chain", issue.ChainID,
				"missing_controls", missing,
			)
		}
	}
	activeIDs := make(map[kernel.ControlID]bool, len(controls))
	for i := range controls {
		activeIDs[controls[i].ID] = true
	}
	resolved := make([]policy.ChainDefinition, 0, len(chains))
	for i := range chains {
		chain := &chains[i]
		// Reject chains with no ControlIDs. The empty slice would
		// otherwise leave allPresent=true (the inner loop never
		// runs) and an empty chain would land in `resolved` —
		// downstream chain evaluation would then trip on a chain
		// that requires zero conditions to fire.
		if len(chain.ControlIDs) == 0 {
			slog.Warn("eval.buildResolvedChains: chain has empty ControlIDs; skipping",
				"chain_id", chain.ID)
			continue
		}
		allPresent := true
		for _, ctlID := range chain.ControlIDs {
			if !activeIDs[ctlID] {
				allPresent = false
				break
			}
		}
		if allPresent {
			resolved = append(resolved, *chain)
		}
	}
	if len(resolved) == 0 {
		return nil
	}
	return resolved
}

func validateBuildDependenciesInput(in *BuildDependenciesInput) error {
	if in.Plan.ControlsPath == "" {
		return errors.New("evaluation plan is required")
	}
	if in.Adapters.ControlLoader == nil {
		return errors.New("control loader is not configured")
	}
	if in.Adapters.ObservationLoader == nil {
		return errors.New("observation loader is not configured")
	}
	if in.Adapters.FindingMarshaler == nil {
		return errors.New("finding marshaler is not configured")
	}
	if in.Adapters.EnrichFn == nil {
		return errors.New("enrich function is not configured")
	}
	return nil
}

// ApplyDeps holds wired dependencies for the apply workflow.
type ApplyDeps struct {
	Runner *AuditWorkflow
	Config AssessmentConfig
}

// Close releases assets held by ApplyDeps. Returns nil today
// because the wired dependencies hold no resources that fail on
// release. The error return reserves the contract: a future
// Close implementation that flushes trace files, closes a tracer
// span, or finalizes a registry must surface those failures so
// the apply pipeline does not silently drop a tail of telemetry.
func (d *ApplyDeps) Close() error { return nil }

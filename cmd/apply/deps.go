package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/exemption"
	"github.com/sufield/stave/internal/adapters/observations"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// Builder encapsulates the cmd-layer resolution needed before building
// apply dependencies. It resolves adapters, loads exemptions, audits
// git status, and delegates final assembly to BuildDependencies.
type Builder struct {
	Logger    *slog.Logger
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Sanitizer kernel.Sanitizer
	Format    appcontracts.OutputFormat
	Digester  ports.Digester
	IDGen     ports.IdentityGenerator

	Opts             *ApplyOptions
	Params           applyParams
	NewFindingWriter compose.FindingWriterFactory
	NewCtlRepo       compose.CtlRepoFactory
	NewStdinObsRepo  func(io.Reader) (appcontracts.ObservationRepository, error)

	// Pre-loaded project config from Resolve(), shared across the pipeline.
	ProjectConfig     *appconfig.ProjectConfig
	ProjectConfigPath string

	// OnObsProgress is called by the observation loader after each file
	// with (processed, total) counts. Optional.
	OnObsProgress func(processed, total int)
}

// NewBuilder constructs a Builder with sensible defaults for crypto.
// Adapter factories (NewFindingWriter, NewCtlRepo, NewStdinObsRepo)
// must be set by the caller before calling Build.
func NewBuilder(logger *slog.Logger, opts *ApplyOptions, params applyParams, sio standardIO) *Builder {
	return &Builder{
		Logger:    logger,
		Stdout:    sio.Stdout,
		Stderr:    sio.Stderr,
		Stdin:     sio.Stdin,
		Sanitizer: sio.Sanitizer,
		Format:    sio.Format,
		Digester:  crypto.NewHasher(),
		IDGen:     crypto.NewHasher(),
		Opts:      opts,
		Params:    params,
	}
}

// Build constructs ApplyDeps from a pre-existing evaluation plan.
// Context is passed as the first argument per Go convention.
func (b *Builder) Build(ctx context.Context, plan *appeval.EvaluationPlan) (*appeval.ApplyDeps, error) {
	if plan == nil {
		return nil, errors.New("evaluation plan is required")
	}

	a, err := b.buildAdapters()
	if err != nil {
		return nil, fmt.Errorf("build adapters: %w", err)
	}

	exemptionCfg, err := loadExemptionConfig(b.Opts.ExemptionFile)
	if err != nil {
		return nil, fmt.Errorf("load exemption config: %w", err)
	}

	gitMeta := compose.AuditGitStatus(plan.ProjectRoot, []string{b.Opts.ControlsDir, b.ProjectConfigPath})

	projCfgInput, err := b.buildProjectConfigFromLoaded(b.ProjectConfig)
	if err != nil {
		return nil, fmt.Errorf("resolve project config: %w", err)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("initialize CEL evaluator: %w", err)
	}

	built, err := appeval.BuildDependencies(ctx, appeval.BuildDependenciesInput{
		Logger: b.Logger,
		Plan:   *plan,
		Adapters: appeval.Adapters{
			FindingMarshaler:  a.marshaler,
			EnrichFn:          buildEnrichFn(b.Sanitizer, b.IDGen),
			ObservationLoader: a.obsLoader,
			ControlLoader:     a.ctlLoader,
		},
		Runtime: appeval.RuntimeConfig{
			MaxUnsafeDuration: b.Params.maxUnsafeDuration,
			Clock:             b.Params.clock,
			Hasher:            b.Digester,
			StaveVersion:      version.String,
			AllowUnknownInput: b.Opts.AllowUnknown,
			ExemptionConfig:   exemptionCfg,
			PredicateParser:   ctlyaml.ParsePredicate,
			CELEvaluator:      celEval,
		},
		Writers: appeval.OutputWriters{
			Stdout: b.Stdout,
			Stderr: b.Stderr,
		},
		Project: appeval.ProjectScope{
			Config:      projCfgInput,
			GitMetadata: gitMeta,
			Filters:     appeval.ControlFilter{},
			ControlsDir: b.Opts.ControlsDir,
		},
	})
	if err != nil {
		return nil, wrapBuildError(err)
	}

	return &appeval.ApplyDeps{Runner: built.Runner, Config: built.Config}, nil
}

type adapters struct {
	marshaler appcontracts.FindingMarshaler
	obsLoader appcontracts.ObservationRepository
	ctlLoader appcontracts.ControlRepository
}

func (b *Builder) buildAdapters() (adapters, error) {
	marshaler, err := b.NewFindingWriter(b.Format, false)
	if err != nil {
		return adapters{}, fmt.Errorf("create finding writer: %w", err)
	}

	obsLoader, err := b.buildObservationLoader(b.Params.source)
	if err != nil {
		return adapters{}, fmt.Errorf("create observation loader: %w", err)
	}

	ctlLoader, err := b.NewCtlRepo()
	if err != nil {
		return adapters{}, fmt.Errorf("create control loader: %w", err)
	}

	return adapters{marshaler: marshaler, obsLoader: obsLoader, ctlLoader: ctlLoader}, nil
}

// buildEnrichFn creates the enrichment function that maps evaluation results
// into findings with remediation plans. Pure function — no closure over builder state.
func buildEnrichFn(sanitizer kernel.Sanitizer, hasher ports.IdentityGenerator) appcontracts.EnrichFunc {
	enricher := remediation.NewMapper(hasher)
	return func(result evaluation.Result) (appcontracts.EnrichedResult, error) {
		return appeval.Enrich(enricher, sanitizer, result)
	}
}

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (b *Builder) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return b.NewStdinObsRepo(b.Stdin)
	}

	var opts []observations.LoaderOption
	if b.Opts.IntegrityManifest != "" {
		opts = append(opts, observations.WithIntegrityCheck(b.Opts.IntegrityManifest, b.Opts.IntegrityPublicKey))
	}
	if b.OnObsProgress != nil {
		opts = append(opts, observations.WithOnProgress(b.OnObsProgress))
	}
	return observations.NewObservationLoader(opts...), nil
}

// buildProjectConfigFromLoaded assembles project configuration input from
// an already-loaded config. This avoids duplicate I/O — the config is loaded
// once in Build() and passed here.
func (b *Builder) buildProjectConfigFromLoaded(projCfg *appconfig.ProjectConfig) (appeval.ProjectConfigInput, error) {
	if projCfg == nil {
		return appeval.ProjectConfigInput{}, nil
	}

	builtinRegistry := ctlbuiltin.NewRegistry(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()))

	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return appeval.ProjectConfigInput{}, fmt.Errorf("initialize embedded pack registry: %w", err)
	}

	return appeval.ProjectConfigInput{
		Exceptions:          mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     convert.ToControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     b.Opts.controlsSet,
		BuiltinLoader:       builtinRegistry.All,
		PackRegistry:        reg,
	}, nil
}

// mapExceptions converts config exception rules to the app-layer input format.
func mapExceptions(in []appconfig.ExceptionRule) []appeval.ExceptionInput {
	if len(in) == 0 {
		return nil
	}
	out := make([]appeval.ExceptionInput, len(in))
	for i, s := range in {
		out[i] = appeval.ExceptionInput{
			ControlID: kernel.ControlID(s.ControlID),
			AssetID:   asset.ID(s.AssetID),
			Reason:    s.Reason,
			Expires:   s.Expires,
		}
	}
	return out
}

// wrapBuildError enriches known dependency errors with user-facing hints.
func wrapBuildError(err error) error {
	return decorateError(err)
}

// loadExemptionConfig loads exemptions from a YAML file. Returns nil if path is empty.
func loadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := (&exemption.Loader{}).Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading exemptions from %q: %w", path, err)
	}
	return cfg, nil
}

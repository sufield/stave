package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/exemption"
	"github.com/sufield/stave/internal/adapters/observations"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/pack"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// Builder encapsulates the cmd-layer resolution needed before building
// apply dependencies. It resolves adapters from the compose provider,
// loads exemptions, audits git status, and delegates final assembly
// to BuildApplyDeps.
type Builder struct {
	Ctx       context.Context
	Logger    *slog.Logger
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Sanitizer kernel.Sanitizer
	Format    ui.OutputFormat
	IsJSON    bool
	Digester  ports.Digester
	IDGen     ports.IdentityGenerator

	Opts     *ApplyOptions
	Params   applyParams
	Provider *compose.Provider

	// OnObsProgress is called by the observation loader after each file
	// with (processed, total) counts. Optional.
	OnObsProgress func(processed, total int)
}

// NewBuilder constructs a Builder from the standard apply execution context.
func NewBuilder(ctx context.Context, logger *slog.Logger, p *compose.Provider, opts *ApplyOptions, params applyParams, sio standardIO) *Builder {
	return &Builder{
		Ctx:       ctx,
		Logger:    logger,
		Stdout:    sio.Stdout,
		Stderr:    sio.Stderr,
		Stdin:     os.Stdin,
		Sanitizer: sio.Sanitizer,
		Format:    sio.Format,
		IsJSON:    sio.IsJSON,
		Digester:  crypto.NewHasher(),
		IDGen:     crypto.NewHasher(),
		Opts:      opts,
		Params:    params,
		Provider:  p,
	}
}

// Build constructs ApplyDeps from a pre-existing evaluation plan.
func (b *Builder) Build(plan *appeval.EvaluationPlan) (*appeval.ApplyDeps, error) {
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

	projCfg, cfgPath, cfgErr := projconfig.FindProjectConfigWithPath("")
	if cfgErr != nil {
		return nil, fmt.Errorf("load project config: %w", cfgErr)
	}
	gitMeta := compose.AuditGitStatus(plan.ProjectRoot, []string{b.Opts.ControlsDir, cfgPath})

	projCfgInput, projCfgErr := b.buildProjectConfigFromLoaded(projCfg)
	if projCfgErr != nil {
		return nil, fmt.Errorf("resolve project config: %w", projCfgErr)
	}

	celEval, celErr := stavecel.NewPredicateEval()
	if celErr != nil {
		return nil, fmt.Errorf("initialize CEL evaluator: %w", celErr)
	}

	deps, err := appeval.BuildApplyDeps(appeval.ApplyBuilderInput{
		Ctx:               b.Ctx,
		Logger:            b.Logger,
		Stdout:            b.Stdout,
		Stderr:            b.Stderr,
		Plan:              *plan,
		Marshaler:         a.marshaler,
		ObsLoader:         a.obsLoader,
		CtlLoader:         a.ctlLoader,
		EnrichFn:          buildEnrichFn(b.Sanitizer, b.IDGen),
		MaxUnsafeDuration: b.Params.maxUnsafeDuration,
		Clock:             b.Params.clock,
		Hasher:            b.Digester,
		AllowUnknownInput: b.Opts.AllowUnknown,
		ExemptionConfig:   exemptionCfg,
		PredicateParser:   ctlyaml.ParsePredicate,
		CELEvaluator:      celEval,
		StaveVersion:      version.String,
		ControlsDir:       b.Opts.ControlsDir,
		ProjectConfig:     projCfgInput,
		GitMetadata:       gitMeta,
		ControlFilters:    appeval.ControlFilter{},
	})
	if err != nil {
		return nil, wrapBuildError(err)
	}

	return deps, nil
}

type adapters struct {
	marshaler appcontracts.FindingMarshaler
	obsLoader appcontracts.ObservationRepository
	ctlLoader appcontracts.ControlRepository
}

func (b *Builder) buildAdapters() (adapters, error) {
	marshaler, err := b.Provider.NewFindingWriter(b.Format, b.IsJSON)
	if err != nil {
		return adapters{}, fmt.Errorf("create finding writer: %w", err)
	}

	obsLoader, err := b.buildObservationLoader(b.Params.source)
	if err != nil {
		return adapters{}, fmt.Errorf("create observation loader: %w", err)
	}

	ctlLoader, err := b.Provider.NewControlRepo()
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
		return b.Provider.NewStdinObsRepo(b.Stdin)
	}

	loader := observations.NewObservationLoader()

	if b.Opts.IntegrityManifest != "" {
		loader.ConfigureIntegrityCheck(b.Opts.IntegrityManifest, b.Opts.IntegrityPublicKey)
	}

	if b.OnObsProgress != nil {
		loader.SetOnProgress(b.OnObsProgress)
	}

	return loader, nil
}

// buildProjectConfigFromLoaded assembles project configuration input from
// an already-loaded config. This avoids duplicate I/O — the config is loaded
// once in Build() and passed here.
func (b *Builder) buildProjectConfigFromLoaded(projCfg *appconfig.ProjectConfig) (appeval.ProjectConfigInput, error) {
	if projCfg == nil {
		return appeval.ProjectConfigInput{}, nil
	}

	builtinRegistry := ctlbuiltin.NewRegistry(ctlbuiltin.EmbeddedFS(), "embedded")

	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return appeval.ProjectConfigInput{}, fmt.Errorf("initialize embedded pack registry: %w", err)
	}

	return appeval.ProjectConfigInput{
		Exceptions:          mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     cmdutil.ToControlIDs(projCfg.ExcludeControls),
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
	cfg, err := exemption.NewLoader().Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading exemptions from %q: %w", path, err)
	}
	return cfg, nil
}

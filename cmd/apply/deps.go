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
)

// Builder encapsulates the cmd-layer resolution needed before building
// apply dependencies. It resolves adapters from the compose provider,
// loads exemptions, audits git status, and delegates final assembly
// to BuildApplyDeps (local to this package).
type Builder struct {
	Ctx       context.Context
	Logger    *slog.Logger
	Stdout    io.Writer
	Stderr    io.Writer
	Sanitizer kernel.Sanitizer
	IsJSON    bool

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
		Sanitizer: sio.Sanitizer,
		IsJSON:    sio.IsJSON,
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

	// Load project config once — both the parsed config and its path are
	// needed downstream (path for git audit, config for evaluation input).
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
		EnrichFn:          b.buildEnrichFn(),
		MaxUnsafe:         b.Params.maxDuration,
		Clock:             b.Params.clock,
		Hasher:            crypto.NewHasher(),
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
		return nil, b.wrapError(err)
	}

	return deps, nil
}

type adapters struct {
	marshaler appcontracts.FindingMarshaler
	obsLoader appcontracts.ObservationRepository
	ctlLoader appcontracts.ControlRepository
}

func (b *Builder) buildAdapters() (adapters, error) {
	format, err := ui.ParseOutputFormat(b.Opts.Format)
	if err != nil {
		return adapters{}, fmt.Errorf("parse output format: %w", err)
	}
	marshaler, err := b.Provider.NewFindingWriter(format, b.IsJSON)
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

func (b *Builder) buildEnrichFn() appcontracts.EnrichFunc {
	enricher := remediation.NewMapper(crypto.NewHasher())
	return func(result evaluation.Result) (appcontracts.EnrichedResult, error) {
		return appeval.Enrich(enricher, b.Sanitizer, result)
	}
}

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (b *Builder) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return b.Provider.NewStdinObsRepo(os.Stdin)
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
		Exceptions:          b.mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     cmdutil.ToControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     b.Opts.ControlsSet,
		BuiltinLoader:       builtinRegistry.All,
		PackRegistry:        reg,
	}, nil
}

func (b *Builder) mapExceptions(in []appconfig.ExceptionRule) []appeval.ExceptionInput {
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

// wrapError enriches known dependency errors with user-facing hints.
func (b *Builder) wrapError(err error) error {
	if errors.Is(err, appeval.ErrConfigConflict) {
		return ui.WithHint(err, ui.ErrHintControlSourceConflict)
	}
	return err
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

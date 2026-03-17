package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	obsjson "github.com/sufield/stave/internal/adapters/input/observations/json"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// Builder encapsulates the cmd-layer resolution needed before building
// apply dependencies. It resolves adapters from the compose provider,
// loads exemptions, audits git status, and delegates final assembly
// to BuildApplyDeps (local to this package).
type Builder struct {
	Ctx       context.Context
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

// BuildWithNewPlan creates a new evaluation plan and builds dependencies from it.
func (b *Builder) BuildWithNewPlan() (*appeval.ApplyDeps, error) {
	plan, err := appeval.NewPlan(b.Opts.buildEvaluatorInput())
	if err != nil {
		return nil, err
	}
	return b.Build(plan)
}

// Build constructs ApplyDeps from a pre-existing evaluation plan.
func (b *Builder) Build(plan *appeval.EvaluationPlan) (*appeval.ApplyDeps, error) {
	if plan == nil {
		return nil, errors.New("evaluation plan is required")
	}

	a, err := b.buildAdapters()
	if err != nil {
		return nil, err
	}

	exemptionCfg, err := LoadExemptionConfig(b.Opts.ExemptionFile)
	if err != nil {
		return nil, err
	}

	_, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	gitMeta := compose.AuditGitStatus(plan.ProjectRoot, []string{b.Opts.ControlsDir, cfgPath})

	deps, err := appeval.BuildApplyDeps(appeval.ApplyBuilderInput{
		Ctx:               b.Ctx,
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
		ToolVersion:       version.Version,
		ControlsDir:       b.Opts.ControlsDir,
		ProjectConfig:     b.buildProjectConfig(),
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
	marshaler, err := b.Provider.NewFindingWriter(b.Opts.Format, b.IsJSON)
	if err != nil {
		return adapters{}, err
	}

	obsLoader, err := b.buildObservationLoader(b.Params.source)
	if err != nil {
		return adapters{}, err
	}

	ctlLoader, err := b.Provider.NewControlRepo()
	if err != nil {
		return adapters{}, fmt.Errorf("create control loader: %w", err)
	}

	return adapters{marshaler: marshaler, obsLoader: obsLoader, ctlLoader: ctlLoader}, nil
}

func (b *Builder) buildEnrichFn() appcontracts.EnrichFunc {
	enricher := remediation.NewMapper(crypto.NewHasher())
	return func(result evaluation.Result) appcontracts.EnrichedResult {
		return appeval.Enrich(enricher, b.Sanitizer, result)
	}
}

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (b *Builder) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return b.Provider.NewStdinObsRepo(os.Stdin)
	}

	loader := obsjson.NewObservationLoader()

	if b.Opts.IntegrityManifest != "" {
		loader.ConfigureIntegrityCheck(b.Opts.IntegrityManifest, b.Opts.IntegrityPublicKey)
	}

	if b.OnObsProgress != nil {
		loader.SetOnProgress(b.OnObsProgress)
	}

	return loader, nil
}

// buildProjectConfig assembles project configuration input from the project config file.
func (b *Builder) buildProjectConfig() appeval.ProjectConfigInput {
	projCfg, ok := projconfig.FindProjectConfig()
	if !ok {
		return appeval.ProjectConfigInput{}
	}

	builtinRegistry := ctlbuiltin.NewRegistry(ctlbuiltin.EmbeddedFS(), "embedded")
	reg, _ := pack.NewEmbeddedRegistry()
	return appeval.ProjectConfigInput{
		Exceptions:          b.mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     cmdutil.ToControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     b.Opts.ControlsSet,
		BuiltinLoader:       builtinRegistry.All,
		PackRegistry:        reg,
	}
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

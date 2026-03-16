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
	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/version"
)

// Builder encapsulates the cmd-layer resolution needed before building
// apply dependencies. It resolves adapters from the compose provider,
// loads exemptions, audits git status, and delegates final assembly
// to appeval.BuildApplyDeps.
type Builder struct {
	Ctx       context.Context
	Stdout    io.Writer
	Stderr    io.Writer
	Sanitizer *sanitize.Sanitizer
	IsJSON    bool

	Opts   *ApplyOptions
	Params applyParams

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

	// 1. Build Adapters
	marshaler, err := compose.ActiveProvider().NewFindingWriter(b.Opts.Format, b.IsJSON)
	if err != nil {
		return nil, err
	}

	obsLoader, err := b.buildObservationLoader(b.Params.source)
	if err != nil {
		return nil, err
	}

	ctlLoader, err := compose.ActiveProvider().NewControlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}

	// 2. Build Metadata & Policy
	exemptionCfg, err := LoadExemptionConfig(b.Opts.ExemptionFile)
	if err != nil {
		return nil, err
	}

	_, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	gitMeta := compose.AuditGitStatus(plan.ProjectRoot, []string{b.Opts.ControlsDir, cfgPath})

	// 3. Assemble Enrichment Logic
	enricher := remediation.NewMapper(crypto.NewHasher())
	enrichFn := func(result evaluation.Result) appcontracts.EnrichedResult {
		return output.Enrich(enricher, b.Sanitizer, result)
	}

	// 4. Final Assembly (delegated to app layer)
	deps, err := appeval.BuildApplyDeps(appeval.ApplyBuilderInput{
		Ctx:               b.Ctx,
		Stdout:            b.Stdout,
		Stderr:            b.Stderr,
		Plan:              *plan,
		Marshaler:         marshaler,
		ObsLoader:         obsLoader,
		CtlLoader:         ctlLoader,
		EnrichFn:          enrichFn,
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

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (b *Builder) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return compose.ActiveProvider().NewStdinObsRepo(os.Stdin)
	}

	loader, err := compose.ActiveProvider().NewObservationRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}

	if b.Opts.IntegrityManifest != "" {
		cfg, ok := loader.(appcontracts.IntegrityCheckConfigurer)
		if !ok {
			return nil, fmt.Errorf("loader %T does not support integrity checks", loader)
		}
		cfg.ConfigureIntegrityCheck(b.Opts.IntegrityManifest, b.Opts.IntegrityPublicKey)
	}

	if b.OnObsProgress != nil {
		if pc, ok := loader.(interface{ SetOnProgress(func(int, int)) }); ok {
			pc.SetOnProgress(b.OnObsProgress)
		}
	}

	return loader, nil
}

// buildProjectConfig assembles project configuration input from the project config file.
func (b *Builder) buildProjectConfig() appeval.ProjectConfigInput {
	projCfg, ok := projconfig.FindProjectConfig()
	if !ok {
		return appeval.ProjectConfigInput{}
	}

	reg, _ := pack.DefaultRegistry()
	return appeval.ProjectConfigInput{
		Exceptions:          b.mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     cmdutil.ToControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     b.Opts.ControlsSet,
		BuiltinLoader:       ctlbuiltin.LoadAll,
		PackRegistry:        reg,
	}
}

func (b *Builder) mapExceptions(in []projconfig.ExceptionRule) []appeval.ExceptionInput {
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

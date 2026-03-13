package apply

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// ApplyDeps holds wired dependencies for the apply command.
type ApplyDeps struct {
	Runner appeval.EvaluateRunner
	Config appeval.EvaluateConfig
}

// Close releases assets held by ApplyDeps.
func (d *ApplyDeps) Close() {}

// Factory encapsulates the construction of ApplyDeps.
type Factory struct {
	cmd    *cobra.Command
	opts   *ApplyOptions
	params applyParams
	// OnObsProgress is called by the observation loader after each file
	// with (processed, total) counts. Optional.
	OnObsProgress func(processed, total int)
}

// NewFactory creates a Factory for building apply dependencies.
func NewFactory(cmd *cobra.Command, opts *ApplyOptions, params applyParams) *Factory {
	return &Factory{cmd: cmd, opts: opts, params: params}
}

// resourceStack groups the intermediate assets created during dependency assembly.
type resourceStack struct {
	marshaler    appcontracts.FindingMarshaler
	enrichFn     appcontracts.EnrichFunc
	obsLoader    appcontracts.ObservationRepository
	ctlLoader    appcontracts.ControlRepository
	exemptionCfg *policy.ExemptionConfig
	gitMeta      *evaluation.GitInfo
}

// BuildWithNewPlan creates a new evaluation plan and builds dependencies from it.
func (f *Factory) BuildWithNewPlan() (*ApplyDeps, error) {
	plan, err := appeval.NewPlan(buildEvaluatorOptions(f.opts))
	if err != nil {
		return nil, err
	}
	return f.Build(plan)
}

// Build constructs ApplyDeps from a pre-existing evaluation plan.
func (f *Factory) Build(plan *appeval.EvaluationPlan) (*ApplyDeps, error) {
	if plan == nil {
		return nil, fmt.Errorf("evaluation plan is required")
	}

	res, err := f.assembleResources(plan)
	if err != nil {
		return nil, err
	}

	buildInput := f.mapToBuildInput(plan, res)

	built, err := appeval.BuildDependencies(buildInput)
	if err != nil {
		return nil, f.wrapError(err)
	}

	compose.WarnIfGitDirty(f.cmd, res.gitMeta, "apply")

	return &ApplyDeps{Runner: built.Runner, Config: built.Config}, nil
}

// assembleResources creates the intermediate assets needed for dependency building.
func (f *Factory) assembleResources(plan *appeval.EvaluationPlan) (resourceStack, error) {
	marshaler, err := compose.NewFindingWriter(f.opts.Format, cmdutil.IsJSONMode(f.cmd))
	if err != nil {
		return resourceStack{}, err
	}
	obsLoader, err := f.buildObservationLoader(f.params.source)
	if err != nil {
		return resourceStack{}, err
	}
	ctlLoader, err := compose.NewControlRepository()
	if err != nil {
		return resourceStack{}, fmt.Errorf("create control loader: %w", err)
	}
	exemptionCfg, err := loadExemptionConfig(f.opts.IgnoreFile)
	if err != nil {
		return resourceStack{}, err
	}

	_, cfgPath, _ := projconfig.FindProjectConfigWithPath()
	gitMeta := compose.CollectGitAudit(plan.ProjectRoot, []string{f.opts.ControlsDir, cfgPath})

	enricher := remediation.NewMapper(crypto.NewHasher())
	san := cmdutil.GetSanitizer(f.cmd)
	enrichFn := func(result evaluation.Result) appcontracts.EnrichedResult {
		return output.Enrich(enricher, san, result)
	}

	return resourceStack{
		marshaler:    marshaler,
		enrichFn:     enrichFn,
		obsLoader:    obsLoader,
		ctlLoader:    ctlLoader,
		exemptionCfg: exemptionCfg,
		gitMeta:      gitMeta,
	}, nil
}

// progressConfigurer sets an optional progress callback on a loader.
type progressConfigurer interface {
	SetOnProgress(fn func(processed, total int))
}

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (f *Factory) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return compose.NewStdinObservationRepository(os.Stdin)
	}
	loader, err := compose.NewObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	if f.opts.IntegrityManifest != "" {
		cfg, ok := loader.(appcontracts.IntegrityCheckConfigurer)
		if !ok {
			return nil, fmt.Errorf("observation loader %T does not support integrity verification", loader)
		}
		cfg.ConfigureIntegrityCheck(f.opts.IntegrityManifest, f.opts.IntegrityPublicKey)
	}
	if f.OnObsProgress != nil {
		if pc, ok := loader.(progressConfigurer); ok {
			pc.SetOnProgress(f.OnObsProgress)
		}
	}
	return loader, nil
}

// mapToBuildInput converts the plan and assets into the input struct for BuildDependencies.
func (f *Factory) mapToBuildInput(plan *appeval.EvaluationPlan, res resourceStack) appeval.BuildDependenciesInput {
	format, _ := compose.ResolveFormatValue(f.cmd, f.opts.Format)
	output := compose.ResolveStdout(f.cmd, cmdutil.QuietEnabled(f.cmd), format)

	return appeval.BuildDependenciesInput{
		Plan:    *plan,
		Context: f.cmd.Context(),
		Adapters: appeval.Adapters{
			FindingMarshaler:  res.marshaler,
			EnrichFn:          res.enrichFn,
			ObservationLoader: res.obsLoader,
			ControlLoader:     res.ctlLoader,
		},
		Runtime: appeval.RuntimeConfig{
			MaxUnsafe:         f.params.maxDuration,
			Clock:             f.params.clock,
			Hasher:            crypto.NewHasher(),
			ToolVersion:       version.Version,
			AllowUnknownInput: f.opts.AllowUnknown,
			ExemptionConfig:   res.exemptionCfg,
			PredicateParser:   ctlyaml.YAMLPredicateParser,
		},
		Writers: appeval.OutputWriters{
			Stdout: output,
			Stderr: f.cmd.ErrOrStderr(),
		},
		Project: appeval.ProjectScope{
			Config:      f.buildProjectConfig(),
			GitMetadata: res.gitMeta,
			Filters:     f.buildFilter(),
			ControlsDir: f.opts.ControlsDir,
		},
	}
}

// buildProjectConfig assembles project configuration input from the project config file.
func (f *Factory) buildProjectConfig() appeval.ProjectConfigInput {
	projCfg, ok := projconfig.FindProjectConfig()
	if !ok {
		return appeval.ProjectConfigInput{}
	}
	reg, _ := pack.DefaultRegistry()
	return appeval.ProjectConfigInput{
		Suppressions:        f.toSuppressions(projCfg.Suppressions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     cmdutil.ToControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     f.opts.ControlsSet,
		BuiltinLoader:       ctlbuiltin.LoadAll,
		PackRegistry:        reg,
	}
}

// buildFilter constructs the control filter from CLI flags.
func (f *Factory) buildFilter() appeval.ControlFilter {
	return appeval.ControlFilter{}
}

// wrapError enriches known dependency errors with user-facing hints.
func (f *Factory) wrapError(err error) error {
	if errors.Is(err, appeval.ErrConfigConflict) {
		return ui.WithHint(err, ui.ErrHintControlSourceConflict)
	}
	return err
}

// toSuppressions converts project suppression rules to evaluator suppression inputs.
func (f *Factory) toSuppressions(in []projconfig.ProjectSuppressionRule) []appeval.SuppressionInput {
	if len(in) == 0 {
		return nil
	}
	out := make([]appeval.SuppressionInput, 0, len(in))
	for _, s := range in {
		out = append(out, appeval.SuppressionInput{
			ControlID: kernel.ControlID(s.ControlID),
			AssetID:   asset.ID(s.AssetID),
			Reason:    s.Reason,
			Expires:   s.Expires,
		})
	}
	return out
}

package apply

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/input/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
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
	params applyParams
}

// NewFactory creates a Factory for building apply dependencies.
func NewFactory(cmd *cobra.Command, params applyParams) *Factory {
	return &Factory{cmd: cmd, params: params}
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
	plan, err := appeval.NewPlan(buildEvaluatorOptions())
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

	warnIfGitDirty(res.gitMeta, "apply")

	return &ApplyDeps{Runner: built.Runner, Config: built.Config}, nil
}

// assembleResources creates the intermediate assets needed for dependency building.
func (f *Factory) assembleResources(plan *appeval.EvaluationPlan) (resourceStack, error) {
	writer, err := cmdutil.NewFindingWriter(applyFlags.outputFormat, cmdutil.IsJSONMode(f.cmd), cmdutil.GetSanitizer(f.cmd))
	if err != nil {
		return resourceStack{}, err
	}
	marshaler, ok := writer.(appcontracts.FindingMarshaler)
	if !ok {
		return resourceStack{}, fmt.Errorf("finding writer does not implement FindingMarshaler")
	}
	obsLoader, err := f.buildObservationLoader(f.params.source)
	if err != nil {
		return resourceStack{}, err
	}
	ctlLoader, err := newControlRepository()
	if err != nil {
		return resourceStack{}, fmt.Errorf("create control loader: %w", err)
	}
	exemptionCfg, err := loadExemptionConfig(applyFlags.ignoreFile)
	if err != nil {
		return resourceStack{}, err
	}

	_, cfgPath, _ := findProjectConfigWithPath()
	gitMeta := collectGitAudit(plan.ProjectRoot, []string{applyFlags.controlsDir, cfgPath})

	enricher := remediation.NewMapper()
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

// buildObservationLoader is a package-level convenience for callers outside Factory.
func buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	return (&Factory{}).buildObservationLoader(source)
}

// buildObservationLoader creates and configures the observation repository,
// selecting stdin or file mode and applying integrity checks if configured.
func (f *Factory) buildObservationLoader(source appeval.ObservationSource) (appcontracts.ObservationRepository, error) {
	if source.IsStdin() {
		return newStdinObservationRepository(os.Stdin)
	}
	loader, err := newObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	if err := appeval.ConfigureIntegrityCheck(loader, applyFlags.applyIntegrityManifest, applyFlags.applyIntegrityPublicKey); err != nil {
		return nil, err
	}
	return loader, nil
}

// mapToBuildInput converts the plan and assets into the input struct for BuildDependencies.
func (f *Factory) mapToBuildInput(plan *appeval.EvaluationPlan, res resourceStack) appeval.BuildDependenciesInput {
	var output io.Writer = os.Stdout
	if applyFlags.quietMode {
		output = io.Discard
	}

	return appeval.BuildDependenciesInput{
		Plan:              *plan,
		FindingMarshaler:  res.marshaler,
		EnrichFn:          res.enrichFn,
		ObservationLoader: res.obsLoader,
		ControlLoader:     res.ctlLoader,
		MaxUnsafe:         f.params.maxDuration,
		Clock:             f.params.clock,
		Output:            output,
		Stderr:            os.Stderr,
		AllowUnknownInput: applyFlags.allowUnknownInput,
		ToolVersion:       version.Version,
		ExemptionConfig:   res.exemptionCfg,
		ProjectConfig:     f.buildProjectConfig(),
		GitMetadata:       res.gitMeta,
		Filters:           f.buildFilter(),
		ControlsDir:       applyFlags.controlsDir,
		PredicateParser:   ctlyaml.YAMLPredicateParser,
	}
}

// buildProjectConfig assembles project configuration input from the project config file.
func (f *Factory) buildProjectConfig() appeval.ProjectConfigInput {
	projCfg, ok := findProjectConfig()
	if !ok {
		return appeval.ProjectConfigInput{}
	}
	return appeval.ProjectConfigInput{
		Suppressions:        f.toSuppressions(projCfg.Suppressions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     toControlIDs(projCfg.ExcludeControls),
		ControlsFlagSet:     applyFlags.applyControlsFlagSet,
		BuiltinLoader:       ctlbuiltin.LoadAll,
	}
}

// buildFilter constructs the control filter from CLI flags.
func (f *Factory) buildFilter() appeval.ControlFilter {
	return appeval.ControlFilter{
		MinSeverity:      policy.ParseSeverity(applyFlags.applyMinSeverity),
		ControlID:        kernel.ControlID(applyFlags.applyControlID),
		ExcludeControlID: toControlIDs(applyFlags.applyExcludeControlIDs),
		Compliance:       applyFlags.applyCompliance,
	}
}

// wrapError enriches known dependency errors with user-facing hints.
func (f *Factory) wrapError(err error) error {
	if strings.Contains(err.Error(), "cannot combine explicit --controls") {
		return ui.WithHint(err, ui.ErrHintControlSourceConflict)
	}
	return err
}

// toSuppressions converts project suppression rules to evaluator suppression inputs.
func (f *Factory) toSuppressions(in []cmdutil.ProjectSuppressionRule) []appeval.SuppressionInput {
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

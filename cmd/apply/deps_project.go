package apply

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/adapters/acknowledgment"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/adapters/exemption"
	"github.com/sufield/stave/internal/adapters/predicate"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// buildProjectConfigFromLoaded assembles project configuration input from
// an already-loaded config. This avoids duplicate I/O — the config is loaded
// once in Build() and passed here.
func (b *Builder) buildProjectConfigFromLoaded(projCfg *appconfig.WorkspacePolicy) (appeval.ProjectConfigInput, error) {
	return buildProjectConfigInput(projCfg, b.Opts.controlsSet)
}

// buildProjectConfigInput converts an already-loaded stave.yaml policy into
// the app-layer ProjectConfigInput the evaluator consumes. Shared by the
// Builder (standard apply path) and buildStaveConfig (cliapi.Apply path) so
// both routes resolve exceptions / exclude_controls / enabled packs from the
// same translation. Returns the zero ProjectConfigInput when projCfg is nil.
func buildProjectConfigInput(projCfg *appconfig.WorkspacePolicy, controlsSet bool) (appeval.ProjectConfigInput, error) {
	if projCfg == nil {
		return appeval.ProjectConfigInput{}, nil
	}

	// Base input carries the settings that need no embedded registry —
	// exceptions and exclude_controls resolve without one. Building this
	// first lets the pack-registry error path return a usable partial
	// input (disclosed fallback) instead of dropping the whole config.
	input := appeval.ProjectConfigInput{
		Exceptions:          mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     projCfg.ExcludeControls,
		ControlsFlagSet:     controlsSet,
		BuiltinLoader:       ctlbuiltin.NewControlStore(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc())).All,
	}

	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return input, fmt.Errorf("initialize embedded pack registry: %w", err)
	}
	input.PackRegistry = reg
	return input, nil
}

// mapExceptions converts config exception rules to the app-layer input format.
// ControlID and AssetID are already typed from YAML deserialization.
func mapExceptions(in []appconfig.PolicyException) []appeval.ExceptionInput {
	if len(in) == 0 {
		return nil
	}
	out := make([]appeval.ExceptionInput, len(in))
	for i, s := range in {
		out[i] = appeval.ExceptionInput{
			ControlID: s.ControlID,
			AssetID:   s.AssetID,
			Reason:    s.Reason,
			Expires:   s.Expires,
		}
	}
	return out
}

// loadAcknowledgmentConfig loads acknowledgments from a YAML file. Returns nil if path is empty.
func loadAcknowledgmentConfig(path string) (*policy.AcknowledgmentConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := acknowledgment.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading acknowledgments from %q: %w", path, err)
	}
	return cfg, nil
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

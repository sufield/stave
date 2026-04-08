package apply

import (
	"fmt"
	"strings"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/exemption"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/builtin/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// buildProjectConfigFromLoaded assembles project configuration input from
// an already-loaded config. This avoids duplicate I/O — the config is loaded
// once in Build() and passed here.
func (b *Builder) buildProjectConfigFromLoaded(projCfg *appconfig.WorkspacePolicy) (appeval.ProjectConfigInput, error) {
	if projCfg == nil {
		return appeval.ProjectConfigInput{}, nil
	}

	builtinRegistry := ctlbuiltin.NewControlStore(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()))

	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return appeval.ProjectConfigInput{}, fmt.Errorf("initialize embedded pack registry: %w", err)
	}

	return appeval.ProjectConfigInput{
		Exceptions:          mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     projCfg.ExcludeControls,
		ControlsFlagSet:     b.Opts.controlsSet,
		BuiltinLoader:       builtinRegistry.All,
		PackRegistry:        reg,
	}, nil
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

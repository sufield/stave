package stave

import (
	"fmt"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// resolveControls loads the control set used by an evaluation. When
// dir is empty the embedded builtin catalog is preloaded and returned
// via ActivePolicies; no ControlRepository is needed. When dir is set,
// the YAML loader is returned and the workflow loads from disk.
//
// Used by [Gate]'s overdue path; the public [Apply] path delegates
// the same logic to applycore.Run.
func resolveControls(dir string) ([]policy.ControlDefinition, appcontracts.ControlRepository, error) {
	if dir != "" {
		loader := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc()))
		return nil, loader, nil
	}
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(),
		"embedded",
		ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		return nil, nil, fmt.Errorf("load builtin controls: %w", err)
	}
	return controls, nil, nil
}

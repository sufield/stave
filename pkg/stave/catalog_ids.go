package stave

import (
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/adapters/controls/builtin"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
)

// CatalogControlIDs returns the sorted set of control IDs in the active
// catalog: the embedded builtin catalog when useBuiltin is true, otherwise the
// controls under controlsDir. Used by `stave compliance` to verify a framework
// mapping references only real controls.
func CatalogControlIDs(controlsDir string, useBuiltin bool) ([]string, error) {
	var ids []string
	if useBuiltin {
		store := builtin.NewControlStore(controldata.FS, "embedded",
			builtin.WithAliasResolver(predicates.ResolverFunc()))
		controls, err := store.All()
		if err != nil {
			return nil, fmt.Errorf("load builtin control catalog: %w", err)
		}
		ids = make([]string, 0, len(controls))
		for i := range controls {
			ids = append(ids, string(controls[i].ID))
		}
	} else {
		controls, err := applycore.LoadControls(controlsDir)
		if err != nil {
			return nil, fmt.Errorf("load controls from %q: %w", controlsDir, err)
		}
		ids = make([]string, 0, len(controls))
		for i := range controls {
			ids = append(ids, string(controls[i].ID))
		}
	}
	slices.Sort(ids)
	return ids, nil
}

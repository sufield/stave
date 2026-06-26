package stave

import (
	"fmt"
	"sort"

	"github.com/sufield/stave/internal/adapters/controls/builtin"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/pack"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
)

// ControlSummary is the minimal control metadata pack resolution needs.
type ControlSummary struct {
	ID       string
	Severity string
}

// CatalogControlSummaries returns the (id, severity) of every control in the
// active catalog — the embedded builtin catalog when useBuiltin is true,
// otherwise the controls under controlsDir. Sorted by ID.
func CatalogControlSummaries(controlsDir string, useBuiltin bool) ([]ControlSummary, error) {
	var out []ControlSummary
	if useBuiltin {
		store := builtin.NewControlStore(controldata.FS, "embedded",
			builtin.WithAliasResolver(predicates.ResolverFunc()))
		controls, err := store.All()
		if err != nil {
			return nil, fmt.Errorf("load builtin control catalog: %w", err)
		}
		out = make([]ControlSummary, 0, len(controls))
		for i := range controls {
			out = append(out, ControlSummary{ID: string(controls[i].ID), Severity: controls[i].Severity.String()})
		}
	} else {
		controls, err := applycore.LoadControls(controlsDir)
		if err != nil {
			return nil, fmt.Errorf("load controls from %q: %w", controlsDir, err)
		}
		out = make([]ControlSummary, 0, len(controls))
		for i := range controls {
			out = append(out, ControlSummary{ID: string(controls[i].ID), Severity: controls[i].Severity.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ResolvePackControls expands one or more concern-pack names into the union of
// their control IDs, resolved against the active catalog. Returns nil for an
// empty packNames (callers then evaluate every control). An unknown pack name
// is an ErrInvalidInput so the CLI maps it to exit 2.
func ResolvePackControls(packNames []string, controlsDir string, useBuiltin bool) ([]string, error) {
	if len(packNames) == 0 {
		return nil, nil
	}
	sums, err := CatalogControlSummaries(controlsDir, useBuiltin)
	if err != nil {
		return nil, err
	}
	metas := make([]pack.ControlMeta, len(sums))
	for i, s := range sums {
		metas[i] = pack.ControlMeta{ID: s.ID, Severity: s.Severity}
	}
	seen := map[string]bool{}
	var ids []string
	for _, name := range packNames {
		p, perr := pack.Load(name)
		if perr != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidInput, perr)
		}
		for _, id := range p.Resolve(metas) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

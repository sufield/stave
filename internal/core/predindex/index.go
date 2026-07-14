package predindex

import (
	"cmp"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Index is a reverse map from property paths to the controls and
// chains that read them, plus per-asset-type metadata. Built
// once from the control catalog and the chain set; consumers
// (gaps, future readiness expansions) look up paths in O(1).
//
// Every map's keys are property paths verbatim from predicate
// AST `field:` references — i.e., they start with "properties."
// — so consumers comparing to observation JSON paths must strip
// that prefix.
type Index struct {
	// PathToControls maps a predicate property path to the
	// sorted, deduplicated list of control IDs whose predicates
	// reference it.
	PathToControls map[string][]kernel.ControlID

	// PathToChains maps a property path to the chain IDs whose
	// member controls collectively reference it. A chain appears
	// once per path regardless of how many of its members touch
	// that path.
	PathToChains map[string][]kernel.ChainID

	// PathMaxSeverity records the highest severity (per
	// controldef.Severity ordering) among the controls reading
	// the path. Empty string when no control declares severity.
	PathMaxSeverity map[string]policy.Severity

	// TypeToPaths is the inverse of applicable_asset_types: per
	// asset type, the set of property paths declared-reading
	// controls reference. Used by the gaps command to know
	// "for an asset of this type, which paths are expected?"
	TypeToPaths map[kernel.AssetType][]string
}

// Build constructs the reverse index from the catalog. The chain
// pass walks every chain's member control IDs and, for each
// member, registers its paths against the chain. Membership is
// deduplicated so a chain reading the same path through three
// members counts once.
func Build(controls []policy.ControlDefinition, chains []policy.ChainDefinition) Index {
	idx := Index{
		PathToControls:  map[string][]kernel.ControlID{},
		PathToChains:    map[string][]kernel.ChainID{},
		PathMaxSeverity: map[string]policy.Severity{},
		TypeToPaths:     map[kernel.AssetType][]string{},
	}

	// controlPaths[ctlID] = []path  — local cache so the chain
	// pass doesn't re-walk every control's AST.
	controlPaths := map[kernel.ControlID][]string{}

	for i := range controls {
		ctl := &controls[i]
		seen := map[string]struct{}{}
		WalkControl(ctl, func(_ kernel.ControlID, _ *policy.PredicateRule, path string) {
			if _, ok := seen[path]; ok {
				return
			}
			seen[path] = struct{}{}
			idx.PathToControls[path] = append(idx.PathToControls[path], ctl.ID)
			controlPaths[ctl.ID] = append(controlPaths[ctl.ID], path)
			if rank(ctl.Severity) > rank(idx.PathMaxSeverity[path]) {
				idx.PathMaxSeverity[path] = ctl.Severity
			}
			for _, at := range ctl.ApplicableAssetTypes {
				idx.TypeToPaths[at] = appendUnique(idx.TypeToPaths[at], path)
			}
		})
	}

	for i := range chains {
		chain := &chains[i]
		chainPaths := map[string]struct{}{}
		for _, memberID := range chain.ControlIDs {
			for _, p := range controlPaths[memberID] {
				chainPaths[p] = struct{}{}
			}
		}
		for p := range chainPaths {
			idx.PathToChains[p] = append(idx.PathToChains[p], chain.ID)
		}
	}

	// Stabilise output: every slice sorted once at the end so
	// downstream consumers and tests see deterministic ordering.
	for k := range idx.PathToControls {
		ids := idx.PathToControls[k]
		slices.SortFunc(ids, func(a, b kernel.ControlID) int {
			return cmp.Compare(a, b)
		})
		idx.PathToControls[k] = slices.Compact(ids)
	}
	for k := range idx.PathToChains {
		ids := idx.PathToChains[k]
		slices.SortFunc(ids, func(a, b kernel.ChainID) int {
			return cmp.Compare(a, b)
		})
		idx.PathToChains[k] = slices.Compact(ids)
	}
	for k := range idx.TypeToPaths {
		paths := idx.TypeToPaths[k]
		slices.Sort(paths)
		idx.TypeToPaths[k] = paths
	}

	return idx
}

// rank gives a comparable score for severity so callers can ask
// "is severity A higher than severity B?" without unmarshalling
// every Severity into a separate enum. critical > high > medium
// > low > anything-else.
func rank(s policy.Severity) int {
	switch s {
	case policy.SeverityCritical:
		return 4
	case policy.SeverityHigh:
		return 3
	case policy.SeverityMedium:
		return 2
	case policy.SeverityLow:
		return 1
	}
	return 0
}

func appendUnique[T comparable](slice []T, v T) []T {
	if slices.Contains(slice, v) {
		return slice
	}
	return append(slice, v)
}


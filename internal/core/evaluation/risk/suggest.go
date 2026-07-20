package risk

import (
	"cmp"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// SuggestChains identifies groups of unchained high/critical controls
// that fire on the same asset. Each group of 2+ co-failing controls
// becomes a suggestion. Controls already participating in fired chains
// are excluded.
//
// failures is the full (control, asset) failure set. chainFindings is
// the set of fired compound findings (used to exclude already-chained
// controls). controlLookup maps control IDs to their definitions for
// severity lookup.
func SuggestChains(
	failures []FailingControl,
	chainFindings []findingsdata.CompoundFinding,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
) []findingsdata.ChainSuggestion {
	chained := chainedControlSetFromFindings(chainFindings)

	// Group unchained high/critical failures by asset.
	type controlOnAsset struct {
		controlID kernel.ControlID
		severity  policy.Severity
	}
	byAsset := make(map[asset.ID][]controlOnAsset)
	seen := make(map[asset.ID]map[kernel.ControlID]struct{})

	for i := range failures {
		cid := failures[i].ControlID
		aid := failures[i].AssetID

		if _, ok := chained[cid]; ok {
			continue
		}
		def := controlLookup[cid]
		if def == nil {
			continue
		}
		if def.Severity != policy.SeverityCritical && def.Severity != policy.SeverityHigh {
			continue
		}

		if seen[aid] == nil {
			seen[aid] = make(map[kernel.ControlID]struct{})
		}
		if _, dup := seen[aid][cid]; dup {
			continue
		}
		seen[aid][cid] = struct{}{}
		byAsset[aid] = append(byAsset[aid], controlOnAsset{
			controlID: cid,
			severity:  def.Severity,
		})
	}

	// Emit a suggestion for each asset with 2+ unchained controls.
	var suggestions []findingsdata.ChainSuggestion
	for aid, controls := range byAsset {
		if len(controls) < 2 {
			continue
		}

		ids := make([]kernel.ControlID, len(controls))
		maxSev := policy.SeverityHigh
		for i, c := range controls {
			ids[i] = c.controlID
			if c.severity == policy.SeverityCritical {
				maxSev = policy.SeverityCritical
			}
		}
		slices.SortFunc(ids, func(a, b kernel.ControlID) int {
			return cmp.Compare(string(a), string(b))
		})

		suggestions = append(suggestions, findingsdata.ChainSuggestion{
			ControlIDs: ids,
			AssetIDs:   []asset.ID{aid},
			Reason:     "co-failing unchained controls on same asset",
			MaxSev:     maxSev,
		})
	}

	// Merge suggestions that share the exact same control set
	// (different assets, same controls co-failing).
	suggestions = mergeSuggestions(suggestions)

	slices.SortFunc(suggestions, func(a, b findingsdata.ChainSuggestion) int {
		if c := cmp.Compare(int(b.MaxSev), int(a.MaxSev)); c != 0 {
			return c
		}
		if c := cmp.Compare(len(b.ControlIDs), len(a.ControlIDs)); c != 0 {
			return c
		}
		return cmp.Compare(string(a.ControlIDs[0]), string(b.ControlIDs[0]))
	})

	return suggestions
}

func chainedControlSetFromFindings(cfs []findingsdata.CompoundFinding) map[kernel.ControlID]struct{} {
	m := make(map[kernel.ControlID]struct{})
	for i := range cfs {
		for _, cid := range cfs[i].ControlsFailing {
			m[cid] = struct{}{}
		}
	}
	return m
}

// mergeSuggestions combines suggestions that have identical control ID
// sets, unioning their asset IDs.
func mergeSuggestions(ss []findingsdata.ChainSuggestion) []findingsdata.ChainSuggestion {
	type key string
	makeKey := func(ids []kernel.ControlID) key {
		var b strings.Builder
		for i, id := range ids {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(string(id))
		}
		return key(b.String())
	}

	idx := make(map[key]int)
	var merged []findingsdata.ChainSuggestion

	for i := range ss {
		k := makeKey(ss[i].ControlIDs)
		if j, ok := idx[k]; ok {
			merged[j].AssetIDs = append(merged[j].AssetIDs, ss[i].AssetIDs...)
		} else {
			idx[k] = len(merged)
			merged = append(merged, ss[i])
		}
	}

	for i := range merged {
		slices.SortFunc(merged[i].AssetIDs, func(a, b asset.ID) int {
			return cmp.Compare(string(a), string(b))
		})
		merged[i].AssetIDs = slices.Compact(merged[i].AssetIDs)
	}

	return merged
}

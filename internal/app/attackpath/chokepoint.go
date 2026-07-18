package attackpath

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// ChokePointAnalysis identifies a control that appears in multiple
// active compound findings. Fixing a choke point breaks multiple
// attack paths simultaneously.
type ChokePointAnalysis struct {
	ControlID        kernel.ControlID `json:"control_id"`
	SharedChainCount int              `json:"shared_chain_count"`
	ChainIDs         []kernel.ChainID `json:"chain_ids"`
}

// FindChokePoints identifies controls shared across multiple compound
// findings. A control appearing in N findings has choke score N.
// Returns controls sorted by choke score descending, then by control
// ID for determinism. Controls appearing in fewer than 2 findings
// are excluded.
func FindChokePoints(cfs []findings.CompoundFinding) []ChokePointAnalysis {
	if len(cfs) == 0 {
		return nil
	}

	controlChains := make(map[kernel.ControlID]map[kernel.ChainID]struct{})
	for i := range cfs {
		for _, cid := range cfs[i].ControlsFailing {
			if controlChains[cid] == nil {
				controlChains[cid] = make(map[kernel.ChainID]struct{})
			}
			controlChains[cid][cfs[i].ChainID] = struct{}{}
		}
	}

	var result []ChokePointAnalysis
	for cid, chains := range controlChains {
		if len(chains) < 2 {
			continue
		}
		ids := make([]kernel.ChainID, 0, len(chains))
		for id := range chains {
			ids = append(ids, id)
		}
		slices.SortFunc(ids, func(a, b kernel.ChainID) int {
			return cmp.Compare(string(a), string(b))
		})
		result = append(result, ChokePointAnalysis{
			ControlID:        cid,
			SharedChainCount: len(chains),
			ChainIDs:         ids,
		})
	}

	slices.SortFunc(result, func(a, b ChokePointAnalysis) int {
		if c := cmp.Compare(b.SharedChainCount, a.SharedChainCount); c != 0 {
			return c
		}
		return cmp.Compare(string(a.ControlID), string(b.ControlID))
	})

	return result
}

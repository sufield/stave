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
	ChainIDs         ChainIDs         `json:"chain_ids"`
}

// ChokePointAnalyses represents a domain collection of ChokePointAnalysis items.
type ChokePointAnalyses []ChokePointAnalysis

// Len returns the count of choke point analysis items.
func (ca ChokePointAnalyses) Len() int {
	return len(ca)
}

// ByControl returns the analysis for a given control ID, or nil if not present.
func (ca ChokePointAnalyses) ByControl(id kernel.ControlID) *ChokePointAnalysis {
	for i := range ca {
		if ca[i].ControlID == id {
			return &ca[i]
		}
	}
	return nil
}

// Top returns the top n choke points.
func (ca ChokePointAnalyses) Top(n int) ChokePointAnalyses {
	if n <= 0 || len(ca) == 0 {
		return nil
	}
	if n >= len(ca) {
		return ca
	}
	return ca[:n]
}

// ControlIDs returns the slice of control IDs identified as choke points.
func (ca ChokePointAnalyses) ControlIDs() []kernel.ControlID {
	out := make([]kernel.ControlID, len(ca))
	for i := range ca {
		out[i] = ca[i].ControlID
	}
	return out
}

// MaxSharedChains returns the highest shared chain count among all choke points (0 if empty).
func (ca ChokePointAnalyses) MaxSharedChains() int {
	if len(ca) == 0 {
		return 0
	}
	return ca[0].SharedChainCount
}

// FindChokePoints identifies controls shared across multiple compound
// findings. A control appearing in N findings has choke score N.
// Returns controls sorted by choke score descending, then by control
// ID for determinism. Controls appearing in fewer than 2 findings
// are excluded.
func FindChokePoints(cfs []findings.CompoundFinding) ChokePointAnalyses {
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

	var result ChokePointAnalyses
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

package rank

import (
	"slices"

	"github.com/sufield/stave/internal/core/report"
)

// BuildBlastIndex returns a map keyed by "controlID@assetID" of the
// per-finding blast-radius score recorded by reachability annotation.
// Findings without a reachability record are absent from the map.
func BuildBlastIndex(a *report.Assessment) map[string]float64 {
	idx := make(map[string]float64, len(a.Findings))
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.Reachability != nil {
			idx[string(f.ControlID)+"@"+string(f.AssetID)] = f.Reachability.BlastRadiusScore.Value()
		}
	}
	return idx
}

// SortByBlastRadius re-orders roadmap entries in place by descending
// blast-radius score, then re-stamps the Rank field. Entries without a
// blast-radius score sort last among themselves in stable order.
func SortByBlastRadius(roadmap *Roadmap, blastIndex map[string]float64) {
	slices.SortFunc(roadmap.Entries, func(a, b PriorityEntry) int {
		as := blastIndex[string(a.ControlID)+"@"+string(a.AssetID)]
		bs := blastIndex[string(b.ControlID)+"@"+string(b.AssetID)]
		if as > bs {
			return -1
		}
		if as < bs {
			return 1
		}
		return 0
	})
	for i := range roadmap.Entries {
		roadmap.Entries[i].Rank = i + 1
	}
}

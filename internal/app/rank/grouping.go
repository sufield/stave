package rank

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/report"
)

// TeamRoadmap groups prioritized entries by team owner, with summary
// statistics (finding count, total risk, SLA breaches, active chains).
type TeamRoadmap struct {
	TeamID       string          `json:"team_id"`
	TeamName     string          `json:"team_name"`
	FindingCount int             `json:"finding_count"`
	TotalRisk    float64         `json:"total_risk_score"`
	SLABreaches  int             `json:"sla_breaches"`
	ActiveChains int             `json:"active_chains"`
	Entries      []PriorityEntry `json:"entries"`
}

// GroupByOwner partitions a roadmap's entries by their team owner,
// resolved through the supplied manifest. Output is sorted by descending
// total risk; ties are broken by team ID for determinism.
//
// Reachability and asset attributes are passed nil to ResolveOwner here
// because the assessment-level lookup is upstream of this grouping —
// callers that need attribute-aware ownership should resolve owners
// before passing entries in.
func GroupByOwner(_ *report.Assessment, roadmap Roadmap, manifest *teams.Manifest) []TeamRoadmap {
	teamMap := make(map[string]*TeamRoadmap)
	for i := range roadmap.Entries {
		e := &roadmap.Entries[i]
		owner := manifest.ResolveOwner(nil, string(e.AssetID), string(e.ControlID))
		tr, ok := teamMap[owner.TeamID]
		if !ok {
			tr = &TeamRoadmap{TeamID: owner.TeamID, TeamName: owner.TeamName}
			teamMap[owner.TeamID] = tr
		}
		tr.FindingCount++
		tr.TotalRisk += e.PriorityScore
		if e.IsOverdue() {
			tr.SLABreaches++
		}
		if e.IsChainMember() {
			tr.ActiveChains++
		}
		tr.Entries = append(tr.Entries, *e)
	}

	out := make([]TeamRoadmap, 0, len(teamMap))
	for _, tr := range teamMap {
		out = append(out, *tr)
	}
	slices.SortFunc(out, func(a, b TeamRoadmap) int {
		if a.TotalRisk > b.TotalRisk {
			return -1
		}
		if a.TotalRisk < b.TotalRisk {
			return 1
		}
		return strings.Compare(a.TeamID, b.TeamID)
	})
	return out
}

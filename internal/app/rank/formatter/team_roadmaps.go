package formatter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// JSONTeamRoadmaps renders a [TeamRoadmaps] payload as indented JSON.
type JSONTeamRoadmaps struct{}

var _ TeamRoadmapsFormatter = (*JSONTeamRoadmaps)(nil)

// Render writes payload as JSON with two-space indentation.
func (JSONTeamRoadmaps) Render(w io.Writer, payload TeamRoadmaps) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal grouped roadmap: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// TextTeamRoadmaps renders the team-by-team breakdown as
// human-readable text. The Roadmap field on the payload is unused
// here because the per-team entries already convey the same data
// in a more useful form for an operator scanning by team.
type TextTeamRoadmaps struct{}

var _ TeamRoadmapsFormatter = (*TextTeamRoadmaps)(nil)

// Render writes the per-team breakdown.
func (TextTeamRoadmaps) Render(w io.Writer, payload TeamRoadmaps) error {
	for _, tr := range payload.TeamRoadmaps {
		if _, err := fmt.Fprintf(w, "\nTEAM: %s (%s)\n", tr.TeamName, tr.TeamID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  Findings: %d  |  Risk Score: %.0f  |  SLA Breaches: %d  |  Active Chains: %d\n",
			tr.FindingCount, tr.TotalRisk, tr.SLABreaches, tr.ActiveChains); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, strings.Repeat("-", 60)); err != nil {
			return err
		}
		for j := range tr.Entries {
			e := &tr.Entries[j]
			if _, err := fmt.Fprintf(w, "  [#%d]  %.1f  %s on %s\n", e.Rank, e.PriorityScore, e.ControlID, e.AssetID); err != nil {
				return err
			}
		}
	}
	return nil
}

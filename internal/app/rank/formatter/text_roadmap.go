package formatter

import (
	"fmt"
	"io"
	"strings"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/core/report"
)

// TextRoadmap renders a Roadmap in human-readable form. ShowReach
// causes blast-radius scores to be printed alongside each entry —
// exposed as a field so callers don't need a second method on the
// interface for the same logic with one parameter flipped.
type TextRoadmap struct {
	ShowReach bool
}

var _ RoadmapFormatter = (*TextRoadmap)(nil)

// Render writes the roadmap to w. Empty roadmaps print a single
// "No findings to rank." line so output is non-empty for shell
// pipelines that pipe through grep.
func (t *TextRoadmap) Render(w io.Writer, rm apprank.Roadmap, assessment *report.Assessment) error {
	if len(rm.Entries) == 0 {
		_, err := fmt.Fprintln(w, "No findings to rank.")
		return err
	}

	if _, err := fmt.Fprintf(w, "REMEDIATION STRATEGY (Top %d Actions)\n", len(rm.Entries)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("=", 50)); err != nil {
		return err
	}

	// Compute the blast index once if ShowReach is set; the previous
	// shape rebuilt it inside the per-entry loop, doing O(N) work
	// per finding for what is structurally an O(N) total cost.
	var blastIdx map[string]float64
	if t.ShowReach && assessment != nil {
		blastIdx = apprank.BuildBlastIndex(assessment)
	}

	for idx := range rm.Entries {
		e := &rm.Entries[idx]
		severity := "HIGH"
		if e.PriorityScore >= 500 {
			severity = "CRITICAL"
		} else if e.PriorityScore < 100 {
			severity = "MEDIUM"
		}

		fmt.Fprintf(w, "\n[#%d]  PRIORITY: %.1f (%s)\n", e.Rank, e.PriorityScore, severity)
		if e.IsChainMember() {
			fmt.Fprintf(w, "      [ATTACK PATH: %s]  %s on %s\n", e.ChainID, e.ControlID, e.AssetID)
		} else {
			fmt.Fprintf(w, "      %s on %s\n", e.ControlID, e.AssetID)
		}
		if blastIdx != nil {
			key := string(e.ControlID) + "@" + string(e.AssetID)
			if score, ok := blastIdx[key]; ok {
				fmt.Fprintf(w, "      Reach: blast_radius=%.0f\n", score)
			} else {
				fmt.Fprintf(w, "      Reach: —\n")
			}
		}
		if e.SLABreached && e.SLAOverdue != "" {
			fmt.Fprintf(w, "      SLA: BREACHED  %s overdue\n", e.SLAOverdue)
		}
		if e.Narrative != "" {
			fmt.Fprintf(w, "      %s\n", e.Narrative)
		}
		fmt.Fprintf(w, "      Risk Impact: %.0f%% of total environment risk  |  Changes: %d  |  Confidence: %.0f%%\n",
			e.RiskImpact, len(e.Changes), e.Confidence*100)

		b := &e.Breakdown
		fmt.Fprintf(w, "      Score: base=%d × duration=%.1f × blast=%.1f × exposure=%.1f",
			b.BaseScore, b.DurationFactor, b.BlastMultiplier, b.ExposureMultiplier)
		if e.SLAUrgency > 1.0 {
			fmt.Fprintf(w, " × sla=%.1f", e.SLAUrgency)
		}
		fmt.Fprintln(w)

		if e.FixAction != "" {
			action := e.FixAction
			if len(action) > 80 {
				action = action[:77] + "..."
			}
			fmt.Fprintf(w, "      Fix: %s\n", action)
		}
	}

	if len(rm.Bundles) > 0 {
		fmt.Fprintf(w, "\nREMEDIATION BUNDLES (Highest ROI)\n")
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for i, b := range rm.Bundles {
			action := b.Action
			if len(action) > 60 {
				action = action[:57] + "..."
			}
			fmt.Fprintf(w, "  %d. Resolve %d findings (risk reduced: %.0f, efficiency: %.1f)\n",
				i+1, b.FindingCount, b.TotalRiskReduced, b.Efficiency)
			fmt.Fprintf(w, "     %s\n", action)
		}
	}
	return nil
}

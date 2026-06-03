package gaps

import (
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// writeText renders the human-readable gap report. Same style
// as stave readiness — grep-friendly prose, no ANSI, sections
// orchestrated by writeText, each section in its own small
// helper to keep cyclomatic complexity below the project's
// gocyclo threshold.
func writeText(w io.Writer, r stave.GapReport, topN int) error {
	if err := writeHeader(w); err != nil {
		return err
	}
	if err := writeGapList(w, r, topN); err != nil {
		return err
	}
	if err := writeSummary(w, r); err != nil {
		return err
	}
	return writeNotes(w, r)
}

func writeHeader(w io.Writer) error {
	return writeLines(w, []string{
		"Stave Field-Level Gap Analysis",
		"==============================",
	})
}

func writeGapList(w io.Writer, r stave.GapReport, topN int) error {
	if len(r.Gaps) == 0 {
		if _, err := fmt.Fprintln(w, "\nNo declared property paths are missing on the observed assets."); err != nil {
			return fmt.Errorf("write gap list: %w", err)
		}
		return nil
	}
	limit := len(r.Gaps)
	if topN > 0 && topN < limit {
		limit = topN
	}
	if _, err := fmt.Fprintf(w, "\nTop %d gaps (of %d total):\n", limit, len(r.Gaps)); err != nil {
		return fmt.Errorf("write gap list header: %w", err)
	}
	for i := range limit {
		if err := writeGap(w, &r.Gaps[i]); err != nil {
			return err
		}
	}
	return nil
}

func writeGap(w io.Writer, g *stave.FieldGap) error {
	if _, err := fmt.Fprintf(w, "\n  #%d  %s\n", g.Priority, g.PropertyPath); err != nil {
		return err
	}
	intent := ""
	if g.IsIntentProperty {
		intent = " [INTENT]"
	}
	if _, err := fmt.Fprintf(w, "      asset_type:    %s%s\n", g.AssetType, intent); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "      missing:       %d of %d observed assets\n", g.MissingCount, g.TotalCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "      unlocks:       %d control(s), %d chain(s)\n", g.ControlsBlockedCount, g.ChainsBlockedCount); err != nil {
		return err
	}
	sev := g.MaxSeverity.String()
	if sev == "" {
		sev = "—"
	}
	if _, err := fmt.Fprintf(w, "      max severity:  %s\n", sev); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "      fix type:      %s (%s)\n", g.Remediation.Type, g.Remediation.Effort); err != nil {
		return err
	}
	if g.Remediation.Command != "" {
		_, err := fmt.Fprintf(w, "      command:       %s\n", g.Remediation.Command)
		return err
	}
	return nil
}

func writeSummary(w io.Writer, r stave.GapReport) error {
	// The per-type breakdown lets the operator read the agent-vs-
	// human split at a glance: tag + derived = "agent loop closes
	// this," api + collector = "needs the human."
	s := r.Summary
	lines := []string{
		"\nSummary",
		"-------",
		fmt.Sprintf("  Total gaps:       %d", s.TotalGaps),
		fmt.Sprintf("                    %d tag, %d derived (fixable by agent)", s.TagGaps, s.DerivedGaps),
		fmt.Sprintf("                    %d api, %d collector (needs operator)", s.ApiGaps, s.CollectorGaps),
		fmt.Sprintf("  Chains blocked:   %d distinct chains across all gaps", s.ChainsBlockedTotal),
	}
	if r.Summary.TopN > 0 {
		lines = append(lines,
			fmt.Sprintf("  Top %d unblocks:   %d chain(s)", r.Summary.TopN, r.Summary.ChainsUnblockedByTopN),
		)
	}
	if r.Summary.QuickWinTimeEstimate != "" {
		lines = append(lines, "  Quick wins:       "+r.Summary.QuickWinTimeEstimate)
	}
	return writeLines(w, lines)
}

func writeNotes(w io.Writer, r stave.GapReport) error {
	lines := []string{"\nNotes:"}
	if r.Summary.IndeterminateDisclaimer != "" {
		lines = append(lines, "  - "+r.Summary.IndeterminateDisclaimer)
	}
	lines = append(lines,
		"  - Intent properties (data_classification, role-type, environment)",
		"    are currently a hardcoded canonical set. A follow-on commit will",
		"    read them from internal/controldata/taxonomy/intent_properties.yaml.",
		"  - Per-asset-ID listings are deferred behind a future --verbose flag.",
		"    Aggregate counts (\"19 of 22\") are the scannable output here.",
	)
	return writeLines(w, lines)
}

func writeLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("write line: %w", err)
		}
	}
	return nil
}

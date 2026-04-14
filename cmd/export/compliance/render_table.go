package compliance

import (
	"fmt"
	"io"
	"strings"
)

func renderTable(w io.Writer, export *EvidenceExport, verbose bool) error { //nolint:unparam // error return for format-dispatch interface consistency
	sep := strings.Repeat("-", 80)

	// Header
	fmt.Fprintf(w, "%s — COMPLIANCE EVIDENCE PACKAGE\n", strings.ToUpper(export.Profile.Name))
	fmt.Fprintf(w, "Snapshot: %s  |  Assessed: %s\n", export.SnapshotID, export.ExportedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(w, "Stave: %s\n\n", export.StaveVersion)

	// Overall score
	fmt.Fprintln(w, "OVERALL POSTURE")
	fmt.Fprintln(w, sep)
	met := export.Score.RequirementsMet
	total := export.Score.RequirementsTotal
	printScoreBar(w, "Overall", met, total)
	fmt.Fprintf(w, "\nStatus breakdown:\n")
	fmt.Fprintf(w, "  Met: %d  |  Not met: %d  |  Not evaluated: %d  |  Incomplete: %d\n\n",
		export.Score.RequirementsMet, export.Score.RequirementsNotMet,
		export.Score.RequirementsNotEval, export.Score.RequirementsIncomp)

	// Requirements table
	fmt.Fprintln(w, "REQUIREMENTS")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%-25s %-30s %-12s %s\n", "Req ID", "Description", "Status", "Controls")
	fmt.Fprintln(w, sep)

	for i := range export.Requirements {
		r := &export.Requirements[i]
		desc := truncate(r.Description, 30)
		status := statusLabel(r.Status)
		ctlSummary := controlCountSummary(r.Controls)
		fmt.Fprintf(w, "%-25s %-30s %-12s %s\n", r.ID, desc, status, ctlSummary)
	}

	// Gap detail
	hasGaps := false
	for i := range export.Requirements {
		if len(export.Requirements[i].Gaps) > 0 {
			hasGaps = true
			break
		}
	}

	if hasGaps {
		fmt.Fprintf(w, "\nGAPS\n")
		fmt.Fprintln(w, sep)

		for i := range export.Requirements {
			r := &export.Requirements[i]
			if len(r.Gaps) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n%s %s [%s — %d gap(s)]\n", r.ID, r.Description, statusLabel(r.Status), len(r.Gaps))

			for j := range r.Gaps {
				g := &r.Gaps[j]
				arn := truncate(g.ResourceARN, 65)
				fmt.Fprintf(w, "  %s  %s\n", g.ControlID, arn)
				fmt.Fprintf(w, "  %s: %s\n", strings.ToUpper(g.Severity), g.Message)

				if verbose {
					renderVerboseTrace(w, export, g.ControlID, g.ResourceARN)
				}
			}
		}
	}

	return nil
}

func renderVerboseTrace(w io.Writer, export *EvidenceExport, controlID, resourceARN string) {
	for i := range export.Evidence {
		e := &export.Evidence[i]
		if e.ControlID != controlID || e.ResourceARN != resourceARN {
			continue
		}
		fmt.Fprintln(w, "  Reasoning trace:")
		if e.ReasoningTrace.InvariantEvaluated != "" {
			fmt.Fprintf(w, "    Invariant: %s\n", e.ReasoningTrace.InvariantEvaluated)
		}
		if len(e.ReasoningTrace.Observations) > 0 {
			fmt.Fprintln(w, "    Observations:")
			for _, o := range e.ReasoningTrace.Observations {
				fmt.Fprintf(w, "      %s = %s\n", o.Field, o.Value)
			}
		}
		break
	}
}

func printScoreBar(w io.Writer, label string, count, total int) {
	width := 20
	filled := 0
	if total > 0 {
		filled = (count * width) / total
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("#", filled) + strings.Repeat(".", width-filled)
	pct := 0.0
	if total > 0 {
		pct = float64(count) / float64(total) * 100
	}
	fmt.Fprintf(w, "  %-12s %s  %d/%d  (%.1f%%)\n", label, bar, count, total, pct)
}

func statusLabel(status string) string {
	switch status {
	case "met":
		return "SATISFIED"
	case "not_met":
		return "NOT MET"
	case "not_evaluated":
		return "NOT EVAL"
	case "incomplete":
		return "INCOMPLETE"
	default:
		return strings.ToUpper(status)
	}
}

func controlCountSummary(controls []ControlSummary) string {
	pass := 0
	total := len(controls)
	for i := range controls {
		if controls[i].FailCount == 0 && controls[i].IncompleteCount == 0 {
			pass++
		}
	}
	return fmt.Sprintf("%d/%d passing", pass, total)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

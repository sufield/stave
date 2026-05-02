package archiveverify

import (
	"fmt"
	"io"
	"strings"
)

// WriteTable writes the attestation in human-readable table format.
func WriteTable(w io.Writer, a *Attestation) {
	fmt.Fprintln(w, "STAVE EVIDENCE ARCHIVE VERIFICATION")
	fmt.Fprintf(w, "Archive:  %s\n", a.ArchivePath)
	fmt.Fprintf(w, "Period:   %s (%s to %s)\n", a.Period.Label,
		a.Period.Start.Format("2006-01-02"), a.Period.End.Format("2006-01-02"))
	fmt.Fprintf(w, "Max gap:  %.0fh\n\n", a.Parameters.MaxGapHours)

	fmt.Fprintln(w, "BUNDLE VERIFICATION")
	fmt.Fprintf(w, "  Discovered:   %d bundles\n", a.Summary.RunsDiscovered)
	fmt.Fprintf(w, "  In period:    %d bundles\n", a.Summary.RunsInPeriod)
	fmt.Fprintf(w, "  Valid:        %d bundles\n", a.Summary.RunsValid)
	if a.Summary.RunsInvalid > 0 {
		fmt.Fprintf(w, "  Invalid:      %d bundles\n", a.Summary.RunsInvalid)
	}
	fmt.Fprintln(w)

	if len(a.InvalidRuns) > 0 {
		fmt.Fprintln(w, "INVALID BUNDLES")
		for _, inv := range a.InvalidRuns {
			fmt.Fprintf(w, "  %s\n", inv.RunID)
			fmt.Fprintf(w, "    Failure: %s\n", inv.FailureReason)
			if inv.Detail != "" {
				fmt.Fprintf(w, "    Detail:  %s\n", inv.Detail)
			}
		}
		fmt.Fprintln(w)
	}

	if len(a.Gaps) > 0 {
		fmt.Fprintf(w, "GAPS DETECTED: %d\n", len(a.Gaps))
		for i, g := range a.Gaps {
			exceeds := "within tolerance"
			if g.ExceedsMax {
				exceeds = "EXCEEDS MAX GAP"
			}
			fmt.Fprintf(w, "  Gap #%d: %s to %s (%.0fh) — %s\n",
				i+1, g.GapStart.Format("2006-01-02T15:04"), g.GapEnd.Format("2006-01-02T15:04"),
				g.DurationHours, exceeds)
		}
		fmt.Fprintln(w)
	}

	sep := strings.Repeat("-", 60)
	fmt.Fprintln(w, "ATTESTATION")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "VERDICT: %s\n", a.Verdict)
	if a.Reason != "" {
		fmt.Fprintf(w, "Reason:  %s\n", a.Reason)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Bundles verified: %d / %d\n", a.Summary.RunsValid, a.Summary.RunsInPeriod)
	fmt.Fprintf(w, "  Gaps > %.0fh:      %d\n", a.Parameters.MaxGapHours, a.Summary.GapsExceedingMax)
	fmt.Fprintf(w, "  Period coverage:  %.1f%%\n", a.Summary.CoveragePct)
	fmt.Fprintln(w, sep)
}

// WriteMarkdown writes the attestation as a markdown document.
func WriteMarkdown(w io.Writer, a *Attestation) {
	verdict := VerdictPass
	if a.IsFail() {
		verdict = VerdictFail
	}

	fmt.Fprintf(w, "# Evidence Archive Attestation — %s\n\n", a.Period.Label)
	fmt.Fprintf(w, "**Generated:** %s  \n", a.GeneratedAt)
	fmt.Fprintf(w, "**Archive:** %s  \n", a.ArchivePath)
	fmt.Fprintf(w, "**Period:** %s to %s  \n",
		a.Period.Start.Format("2006-01-02"), a.Period.End.Format("2006-01-02"))
	fmt.Fprintf(w, "**Verdict:** %s\n\n", verdict)

	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Metric | Value |")
	fmt.Fprintln(w, "|--------|-------|")
	fmt.Fprintf(w, "| Bundles verified | %d / %d |\n", a.Summary.RunsValid, a.Summary.RunsInPeriod)
	fmt.Fprintf(w, "| Gaps > %.0fh | %d |\n", a.Parameters.MaxGapHours, a.Summary.GapsExceedingMax)
	fmt.Fprintf(w, "| Period coverage | %.1f%% |\n", a.Summary.CoveragePct)
	fmt.Fprintln(w)

	if len(a.InvalidRuns) > 0 {
		fmt.Fprintln(w, "## Invalid Bundles")
		fmt.Fprintln(w)
		for _, inv := range a.InvalidRuns {
			fmt.Fprintf(w, "### %s\n", inv.RunID)
			fmt.Fprintf(w, "- **Failure:** %s\n", inv.FailureReason)
			if inv.Detail != "" {
				fmt.Fprintf(w, "- **Detail:** %s\n", inv.Detail)
			}
			fmt.Fprintln(w)
		}
	}

	if len(a.Gaps) > 0 {
		fmt.Fprintln(w, "## Gaps")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Start | End | Duration | Exceeds Max |")
		fmt.Fprintln(w, "|-------|-----|----------|-------------|")
		for _, g := range a.Gaps {
			exceeds := "No"
			if g.ExceedsMax {
				exceeds = "Yes"
			}
			fmt.Fprintf(w, "| %s | %s | %.0fh | %s |\n",
				g.GapStart.Format("2006-01-02T15:04"), g.GapEnd.Format("2006-01-02T15:04"),
				g.DurationHours, exceeds)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "## Attestation Statement")
	fmt.Fprintln(w)
	if a.IsPass() {
		fmt.Fprintf(w, "This archive demonstrates continuous, tamper-evident security monitoring for %s.\n", a.Period.Label)
	} else {
		fmt.Fprintf(w, "This archive **does not** demonstrate continuous monitoring for %s. %s\n", a.Period.Label, a.Reason)
	}
}

package archiveverify

import (
	"fmt"
	"io"
	"strings"
)

// stickyWriter captures the first write error and turns subsequent
// writes into no-ops. The format functions emit dozens of Fprintln/
// Fprintf calls; checking each return inline would balloon the body
// and obscure the layout. The sticky pattern lets the formatters
// stay readable while still surfacing a real I/O failure (full disk,
// closed pipe) to the caller via Err().
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// WriteTable writes the attestation in human-readable table format.
// Returns the first I/O error encountered, or nil on success.
func WriteTable(w io.Writer, a *Attestation) error {
	sw := &stickyWriter{w: w}
	fmt.Fprintln(sw, "STAVE EVIDENCE ARCHIVE VERIFICATION")
	fmt.Fprintf(sw, "Archive:  %s\n", a.ArchivePath)
	fmt.Fprintf(sw, "Period:   %s (%s to %s)\n", a.Period.Label,
		a.Period.Start.Format("2006-01-02"), a.Period.End.Format("2006-01-02"))
	fmt.Fprintf(sw, "Max gap:  %.0fh\n\n", a.Parameters.MaxGapHours)

	fmt.Fprintln(sw, "BUNDLE VERIFICATION")
	fmt.Fprintf(sw, "  Discovered:   %d bundles\n", a.Summary.RunsDiscovered)
	fmt.Fprintf(sw, "  In period:    %d bundles\n", a.Summary.RunsInPeriod)
	fmt.Fprintf(sw, "  Valid:        %d bundles\n", a.Summary.RunsValid)
	if a.Summary.RunsInvalid > 0 {
		fmt.Fprintf(sw, "  Invalid:      %d bundles\n", a.Summary.RunsInvalid)
	}
	fmt.Fprintln(sw)

	if len(a.InvalidRuns) > 0 {
		fmt.Fprintln(sw, "INVALID BUNDLES")
		for _, inv := range a.InvalidRuns {
			fmt.Fprintf(sw, "  %s\n", inv.RunID)
			fmt.Fprintf(sw, "    Failure: %s\n", inv.FailureReason)
			if inv.Detail != "" {
				fmt.Fprintf(sw, "    Detail:  %s\n", inv.Detail)
			}
		}
		fmt.Fprintln(sw)
	}

	if len(a.Gaps) > 0 {
		fmt.Fprintf(sw, "GAPS DETECTED: %d\n", len(a.Gaps))
		for i, g := range a.Gaps {
			exceeds := "within tolerance"
			if g.ExceedsMax {
				exceeds = "EXCEEDS MAX GAP"
			}
			fmt.Fprintf(sw, "  Gap #%d: %s to %s (%.0fh) — %s\n",
				i+1, g.GapStart.Format("2006-01-02T15:04"), g.GapEnd.Format("2006-01-02T15:04"),
				g.DurationHours, exceeds)
		}
		fmt.Fprintln(sw)
	}

	sep := strings.Repeat("-", 60)
	fmt.Fprintln(sw, "ATTESTATION")
	fmt.Fprintln(sw, sep)
	fmt.Fprintf(sw, "VERDICT: %s\n", a.Verdict)
	if a.Reason != "" {
		fmt.Fprintf(sw, "Reason:  %s\n", a.Reason)
	}
	fmt.Fprintln(sw)
	fmt.Fprintf(sw, "  Bundles verified: %d / %d\n", a.Summary.RunsValid, a.Summary.RunsInPeriod)
	fmt.Fprintf(sw, "  Gaps > %.0fh:      %d\n", a.Parameters.MaxGapHours, a.Summary.GapsExceedingMax)
	fmt.Fprintf(sw, "  Period coverage:  %.1f%%\n", a.Summary.CoveragePct)
	fmt.Fprintln(sw, sep)
	return sw.err
}

// WriteMarkdown writes the attestation as a markdown document.
// Returns the first I/O error encountered, or nil on success.
func WriteMarkdown(w io.Writer, a *Attestation) error {
	sw := &stickyWriter{w: w}
	verdict := VerdictPass
	if a.IsFail() {
		verdict = VerdictFail
	}

	fmt.Fprintf(sw, "# Evidence Archive Attestation — %s\n\n", a.Period.Label)
	fmt.Fprintf(sw, "**Generated:** %s  \n", a.GeneratedAt)
	fmt.Fprintf(sw, "**Archive:** %s  \n", a.ArchivePath)
	fmt.Fprintf(sw, "**Period:** %s to %s  \n",
		a.Period.Start.Format("2006-01-02"), a.Period.End.Format("2006-01-02"))
	fmt.Fprintf(sw, "**Verdict:** %s\n\n", verdict)

	fmt.Fprintln(sw, "## Summary")
	fmt.Fprintln(sw)
	fmt.Fprintln(sw, "| Metric | Value |")
	fmt.Fprintln(sw, "|--------|-------|")
	fmt.Fprintf(sw, "| Bundles verified | %d / %d |\n", a.Summary.RunsValid, a.Summary.RunsInPeriod)
	fmt.Fprintf(sw, "| Gaps > %.0fh | %d |\n", a.Parameters.MaxGapHours, a.Summary.GapsExceedingMax)
	fmt.Fprintf(sw, "| Period coverage | %.1f%% |\n", a.Summary.CoveragePct)
	fmt.Fprintln(sw)

	if len(a.InvalidRuns) > 0 {
		fmt.Fprintln(sw, "## Invalid Bundles")
		fmt.Fprintln(sw)
		for _, inv := range a.InvalidRuns {
			fmt.Fprintf(sw, "### %s\n", inv.RunID)
			fmt.Fprintf(sw, "- **Failure:** %s\n", inv.FailureReason)
			if inv.Detail != "" {
				fmt.Fprintf(sw, "- **Detail:** %s\n", inv.Detail)
			}
			fmt.Fprintln(sw)
		}
	}

	if len(a.Gaps) > 0 {
		fmt.Fprintln(sw, "## Gaps")
		fmt.Fprintln(sw)
		fmt.Fprintln(sw, "| Start | End | Duration | Exceeds Max |")
		fmt.Fprintln(sw, "|-------|-----|----------|-------------|")
		for _, g := range a.Gaps {
			exceeds := "No"
			if g.ExceedsMax {
				exceeds = "Yes"
			}
			fmt.Fprintf(sw, "| %s | %s | %.0fh | %s |\n",
				g.GapStart.Format("2006-01-02T15:04"), g.GapEnd.Format("2006-01-02T15:04"),
				g.DurationHours, exceeds)
		}
		fmt.Fprintln(sw)
	}

	fmt.Fprintln(sw, "## Attestation Statement")
	fmt.Fprintln(sw)
	if a.IsPass() {
		fmt.Fprintf(sw, "This archive demonstrates continuous, tamper-evident security monitoring for %s.\n", a.Period.Label)
	} else {
		fmt.Fprintf(sw, "This archive **does not** demonstrate continuous monitoring for %s. %s\n", a.Period.Label, a.Reason)
	}
	return sw.err
}

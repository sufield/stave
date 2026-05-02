package execreport

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"
)

// WriteMarkdown writes the report as a markdown document. Returns the
// first write error encountered. Callers must check the result —
// silently dropping a write error against an os.File leaves the user
// with a truncated, unsignalled report on disk.
func WriteMarkdown(w io.Writer, r *Report) error {
	ew := &writeErrTracker{w: w}
	writeMarkdownTo(ew, r)
	return ew.err
}

// writeErrTracker wraps an io.Writer and records the first error.
// Subsequent Write calls become no-ops so the surrounding format
// helpers don't need to check after every line.
type writeErrTracker struct {
	w   io.Writer
	err error
}

func (e *writeErrTracker) Write(p []byte) (int, error) {
	if e.err != nil {
		// Subsequent writes are silently swallowed: the error has
		// already been captured on the tracker and will be returned
		// from WriteMarkdown. Returning the error from every Write
		// would break fmt.Fprintf which short-circuits on non-nil
		// err and would prevent the rest of the document from
		// laying out cleanly into a buffer the caller may discard
		// anyway.
		return len(p), nil //nolint:nilerr // intentional: error already captured on tracker
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

func writeMarkdownTo(w io.Writer, r *Report) {
	fmt.Fprintf(w, "# %s — %s\n\n", r.Title, r.Period)
	fmt.Fprintf(w, "**Generated:** %s\n\n", r.GeneratedAt)

	// Posture.
	arrow := ""
	if r.Posture.Delta30d > 0 {
		arrow = " ↑"
	} else if r.Posture.Delta30d < 0 {
		arrow = " ↓"
	}
	fmt.Fprintln(w, "## Posture Score")
	fmt.Fprintf(w, "\n**%.1f** (%s) — %+.1f in 30 days%s\n\n", r.Posture.Score, r.Posture.Band, r.Posture.Delta30d, arrow)

	// Findings.
	fmt.Fprintln(w, "## Findings Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Open |")
	fmt.Fprintln(w, "|----------|------|")
	fmt.Fprintf(w, "| Critical | %d |\n", r.FindingsSummary.Critical)
	fmt.Fprintf(w, "| High | %d |\n", r.FindingsSummary.High)
	fmt.Fprintf(w, "| Medium | %d |\n", r.FindingsSummary.Medium)
	fmt.Fprintf(w, "| Low | %d |\n", r.FindingsSummary.Low)
	fmt.Fprintf(w, "| **Total** | **%d** |\n\n", r.FindingsSummary.Total)

	// SLA.
	if r.SLA != nil {
		fmt.Fprintf(w, "## SLA Compliance (%s)\n\n", r.SLA.ProfileName)
		fmt.Fprintf(w, "Overall: %.1f%%\n\n", r.SLA.CompliancePct)
		fmt.Fprintln(w, "| Severity | Within SLA | Breached | Compliance |")
		fmt.Fprintln(w, "|----------|-----------|----------|------------|")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if s, ok := r.SLA.BySeverity[sev]; ok {
				fmt.Fprintf(w, "| %s | %d/%d | %d | %.1f%% |\n",
					strutil.TitleCase(sev), s.Within, s.Total, s.Breached, s.Pct)
			}
		}
		fmt.Fprintln(w)
	}

	// Top findings.
	if len(r.TopFindings) > 0 {
		fmt.Fprintln(w, "## Top Findings")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Rank | Control | Severity | Dwell | SLA |")
		fmt.Fprintln(w, "|------|---------|----------|-------|-----|")
		for i := range r.TopFindings {
			f := &r.TopFindings[i]
			sla := ""
			if f.IsAnyBreach() {
				sla = "BREACHED"
			}
			fmt.Fprintf(w, "| %d | %s | %s | %.0fh | %s |\n",
				f.Rank, f.ControlID, strings.ToUpper(f.Severity), f.DwellHours, sla)
		}
		fmt.Fprintln(w)
	}

	// Chains.
	if r.Chains.ActiveCount > 0 {
		fmt.Fprintln(w, "## Active Compound Chains")
		fmt.Fprintln(w)
		for _, c := range r.Chains.Active {
			fmt.Fprintf(w, "### %s (%s)\n\n", c.ChainID, strings.ToUpper(c.Severity))
			if c.Narrative != "" {
				fmt.Fprintf(w, "%s\n\n", c.Narrative)
			}
			fmt.Fprintf(w, "Members: %s\n\n", strings.Join(c.Members, ", "))
		}
	}

	// ATT&CK.
	fmt.Fprintf(w, "## ATT&CK Coverage\n\n%d/%d tactics covered (%.0f%%)\n\n",
		r.AttackCoverage.TacticsCovered, r.AttackCoverage.TacticsTotal, r.AttackCoverage.CoveragePct)

	// Framework readiness.
	if len(r.FrameworkReady) > 0 {
		fmt.Fprintln(w, "## Framework Readiness")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Framework | Passing | Total | Readiness |")
		fmt.Fprintln(w, "|-----------|---------|-------|-----------|")
		for _, fw := range r.FrameworkReady {
			fmt.Fprintf(w, "| %s | %d | %d | %.1f%% |\n", fw.Framework, fw.Passing, fw.Total, fw.ReadinessPct)
		}
		fmt.Fprintln(w)
	}

	// Teams.
	if len(r.Teams) > 0 {
		fmt.Fprintln(w, "## Team Posture")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Team | Score | Trend | Critical | SLA% |")
		fmt.Fprintln(w, "|------|-------|-------|----------|------|")
		for _, t := range r.Teams {
			fmt.Fprintf(w, "| %s | %.1f | %s | %d | %.0f%% |\n", t.Name, t.Score, t.Trajectory, t.CriticalOpen, t.SLACompPct)
		}
		fmt.Fprintln(w)
	}

	// Executive summary.
	fmt.Fprintln(w, "## Executive Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, r.ExecutiveSummary.Paragraph)
	for _, a := range r.ExecutiveSummary.Attention {
		fmt.Fprintf(w, "\n**Attention required:** %s — %s", a.Subject, a.Reason)
		if a.Contact != "" {
			fmt.Fprintf(w, " Contact: %s", a.Contact)
		}
		fmt.Fprintln(w)
	}
}

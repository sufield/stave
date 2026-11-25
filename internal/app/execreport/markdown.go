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

	writePostureSection(w, r.Posture)
	writeFindingsSummarySection(w, r.FindingsSummary)
	writeSLASection(w, r.SLA)
	writeTopFindingsSection(w, r.TopFindings)
	if r.Chains.ActiveCount > 0 {
		writeActiveChains(w, r.Chains.Active)
	}
	fmt.Fprintf(w, "## ATT&CK Coverage\n\n%d/%d tactics covered (%.0f%%)\n\n",
		r.AttackCoverage.TacticsCovered, r.AttackCoverage.TacticsTotal, r.AttackCoverage.CoveragePct)
	writeFrameworkSection(w, r.FrameworkReady)
	writeTeamsSection(w, r.Teams)
	writeExecutiveSummarySection(w, r.ExecutiveSummary)
}

func writePostureSection(w io.Writer, p PostureSection) {
	arrow := ""
	if p.Delta30d > 0 {
		arrow = " ↑"
	} else if p.Delta30d < 0 {
		arrow = " ↓"
	}
	fmt.Fprintln(w, "## Posture Score")
	fmt.Fprintf(w, "\n**%.1f** (%s) — %+.1f in 30 days%s\n\n", p.Score, p.Band, p.Delta30d, arrow)
}

func writeFindingsSummarySection(w io.Writer, f FindingsSummary) {
	fmt.Fprintln(w, "## Findings Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Severity | Open |")
	fmt.Fprintln(w, "|----------|------|")
	fmt.Fprintf(w, "| Critical | %d |\n", f.Critical)
	fmt.Fprintf(w, "| High | %d |\n", f.High)
	fmt.Fprintf(w, "| Medium | %d |\n", f.Medium)
	fmt.Fprintf(w, "| Low | %d |\n", f.Low)
	fmt.Fprintf(w, "| **Total** | **%d** |\n\n", f.Total)
}

func writeSLASection(w io.Writer, sla *SLASection) {
	if sla == nil {
		return
	}
	fmt.Fprintf(w, "## SLA Compliance (%s)\n\n", sla.ProfileName)
	fmt.Fprintf(w, "Overall: %.1f%%\n\n", sla.CompliancePct)
	fmt.Fprintln(w, "| Severity | Within SLA | Breached | Compliance |")
	fmt.Fprintln(w, "|----------|-----------|----------|------------|")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if s, ok := sla.BySeverity[sev]; ok {
			fmt.Fprintf(w, "| %s | %d/%d | %d | %.1f%% |\n",
				strutil.TitleCase(sev), s.Within, s.Total, s.Breached, s.Pct)
		}
	}
	fmt.Fprintln(w)
}

func writeTopFindingsSection(w io.Writer, findings []TopFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w, "## Top Findings")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Rank | Control | Severity | Dwell | SLA |")
	fmt.Fprintln(w, "|------|---------|----------|-------|-----|")
	for i := range findings {
		f := &findings[i]
		sla := ""
		if f.IsAnyBreach() {
			sla = "BREACHED"
		}
		fmt.Fprintf(w, "| %d | %s | %s | %.0fh | %s |\n",
			f.Rank, f.ControlID, strings.ToUpper(f.Severity.String()), f.DwellHours, sla)
	}
	fmt.Fprintln(w)
}

func writeFrameworkSection(w io.Writer, frameworks []FrameworkReadiness) {
	if len(frameworks) == 0 {
		return
	}
	fmt.Fprintln(w, "## Framework Readiness")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Framework | Passing | Total | Readiness |")
	fmt.Fprintln(w, "|-----------|---------|-------|-----------|")
	for _, fw := range frameworks {
		fmt.Fprintf(w, "| %s | %d | %d | %.1f%% |\n", fw.Framework, fw.Passing, fw.Total, fw.ReadinessPct)
	}
	fmt.Fprintln(w)
}

func writeTeamsSection(w io.Writer, teams []TeamSection) {
	if len(teams) == 0 {
		return
	}
	fmt.Fprintln(w, "## Team Posture")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Team | Score | Trend | Critical | SLA% |")
	fmt.Fprintln(w, "|------|-------|-------|----------|------|")
	for _, t := range teams {
		fmt.Fprintf(w, "| %s | %.1f | %s | %d | %.0f%% |\n", t.Name, t.Score, t.Trajectory, t.CriticalOpen, t.SLACompPct)
	}
	fmt.Fprintln(w)
}

func writeExecutiveSummarySection(w io.Writer, es ExecutiveSummary) {
	fmt.Fprintln(w, "## Executive Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, es.Paragraph)
	for _, a := range es.Attention {
		fmt.Fprintf(w, "\n**Attention required:** %s — %s", a.Subject, a.Reason)
		if a.Contact != "" {
			fmt.Fprintf(w, " Contact: %s", a.Contact)
		}
		fmt.Fprintln(w)
	}
}

func writeActiveChains(w io.Writer, chains []ActiveChain) {
	fmt.Fprintln(w, "## Active Compound Chains")
	fmt.Fprintln(w)
	for _, c := range chains {
		fmt.Fprintf(w, "### %s (%s)\n\n", c.ChainID, strings.ToUpper(c.Severity.String()))
		if c.Narrative != "" {
			fmt.Fprintf(w, "%s\n\n", c.Narrative)
		}
		memberStrs := make([]string, len(c.Members))
		for i, m := range c.Members {
			memberStrs[i] = string(m)
		}
		fmt.Fprintf(w, "Members: %s\n\n", strings.Join(memberStrs, ", "))
	}
}

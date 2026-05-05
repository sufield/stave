package plan

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"
)

// errWriter wraps an io.Writer and remembers the first write error
// so the WriteMarkdown / WriteText helpers can stop emitting on the
// first failure and surface it once at the end. The earlier shape
// discarded every fmt.Fprintf return, so a closed pipe or a full
// disk produced silently truncated output and the command still
// reported success.
type errWriter struct {
	w   io.Writer
	err error
}

// Write satisfies io.Writer so every existing fmt.Fprintf(ew, ...)
// call site flows through here. Once err is sticky every subsequent
// write becomes a no-op, so the helpers do not need to check after
// each call.
func (e *errWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// WriteMarkdown writes the plan as a markdown document. Returns the
// first sticky write error (typically a closed downstream pipe or a
// full disk); nil on a clean run.
func WriteMarkdown(w io.Writer, p *Plan) error {
	ew := &errWriter{w: w}
	// fmt.Fprint return values are intentionally discarded throughout:
	// the sticky-error gate in errWriter captures the first failure
	// and short-circuits subsequent writes, so per-call checks would
	// duplicate the bookkeeping. The function returns ew.err at the
	// end as the single source of truth.
	for i := range p.Teams {
		if i > 0 {
			_, _ = fmt.Fprint(ew, "\n---\n\n")
		}
		writeTeamMarkdown(ew, &p.Teams[i], p)
	}

	if len(p.Unattributed) > 0 {
		_, _ = fmt.Fprint(ew, "\n---\n\n")
		fmt.Fprintln(ew, "## Unattributed Findings")
		fmt.Fprintln(ew)
		fmt.Fprintln(ew, "These findings could not be attributed to any team. Update team-manifest.yaml to assign ownership.")
		fmt.Fprintln(ew)
		fmt.Fprintln(ew, "| Control | Asset | Severity |")
		fmt.Fprintln(ew, "|---------|-------|----------|")
		for i := range p.Unattributed {
			f := &p.Unattributed[i]
			fmt.Fprintf(ew, "| %s | %s | %s |\n", f.ControlID, truncate(f.AssetID, 40), strings.ToUpper(f.Severity.String()))
		}
	}
	return ew.err
}

func writeTeamMarkdown(w io.Writer, tp *TeamPlan, p *Plan) {
	fmt.Fprintf(w, "# Remediation Plan — %s\n", tp.TeamName)
	fmt.Fprintf(w, "Generated: %s\n", p.GeneratedAt)
	if p.SLAProfile != "" {
		fmt.Fprintf(w, "SLA Profile: %s\n", p.SLAProfile)
	}
	fmt.Fprintln(w)
	if tp.Contact != "" {
		fmt.Fprintf(w, "**Team contact:** %s\n", tp.Contact)
	}
	fmt.Fprintf(w, "**Open findings:** %d (%d critical, %d high, %d medium)\n",
		tp.Summary.Total, tp.Summary.Critical, tp.Summary.High, tp.Summary.Medium)
	if tp.Summary.SLABreached > 0 {
		fmt.Fprintf(w, "**SLA compliance:** %.0f%% — %d findings past deadline\n",
			tp.Summary.SLACompPct, tp.Summary.SLABreached)
	}
	fmt.Fprintln(w)

	// Group findings by severity.
	sevGroups := map[string][]PlanFinding{}
	for i := range tp.Findings {
		sev := tp.Findings[i].Severity.String()
		sevGroups[sev] = append(sevGroups[sev], tp.Findings[i])
	}

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		findings := sevGroups[sev]
		if len(findings) == 0 {
			continue
		}
		heading := sevHeading(sev)
		fmt.Fprintf(w, "## %s\n\n", heading)
		for i := range findings {
			writeFindingMarkdown(w, &findings[i])
		}
	}

	// Compliance appendix.
	if hasCompliance(tp.Findings) {
		fmt.Fprintln(w, "## Compliance Citations")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Finding | Frameworks |")
		fmt.Fprintln(w, "|---------|-----------|")
		for i := range tp.Findings {
			f := &tp.Findings[i]
			if len(f.Compliance) == 0 {
				continue
			}
			var fws []string
			for fw, cite := range f.Compliance {
				fws = append(fws, fw+": "+cite)
			}
			slices.Sort(fws)
			fmt.Fprintf(w, "| %s | %s |\n", f.ControlID, strings.Join(fws, ", "))
		}
		fmt.Fprintln(w)
	}
}

func writeFindingMarkdown(w io.Writer, f *PlanFinding) {
	fmt.Fprintf(w, "### %d. %s\n", f.Rank, f.ControlID)
	if f.ControlName != "" {
		fmt.Fprintf(w, "**%s**\n\n", f.ControlName)
	}

	fmt.Fprintln(w, "| Field | Value |")
	fmt.Fprintln(w, "|-------|-------|")
	fmt.Fprintf(w, "| Severity | %s |\n", strings.ToUpper(f.Severity.String()))
	fmt.Fprintf(w, "| Asset | %s |\n", f.AssetID)
	fmt.Fprintf(w, "| Dwell time | %.0f hours |\n", f.DwellHours)
	if f.SLADeadlineHours != nil {
		fmt.Fprintf(w, "| SLA deadline | %.0fh |\n", *f.SLADeadlineHours)
		if f.SLABreached && f.OverdueHours != nil {
			fmt.Fprintf(w, "| SLA status | BREACHED — %.0fh overdue |\n", *f.OverdueHours)
		} else {
			fmt.Fprintf(w, "| SLA status | Within SLA |\n")
		}
	}
	fmt.Fprintln(w)

	if f.RemediationAction != "" {
		fmt.Fprintln(w, "**Remediation:**")
		fmt.Fprintf(w, "```\n%s\n```\n\n", strings.TrimSpace(f.RemediationAction))
	}
}

// WriteText writes the plan in plain text format. Returns the first
// sticky write error captured by errWriter; nil on a clean run.
func WriteText(w io.Writer, p *Plan) error {
	ew := &errWriter{w: w}
	for i := range p.Teams {
		tp := &p.Teams[i]
		name := tp.TeamName
		if name == "" {
			name = tp.TeamID
		}
		fmt.Fprintf(ew, "REMEDIATION PLAN — %s\n", strings.ToUpper(name))
		fmt.Fprintf(ew, "Generated: %s\n", p.GeneratedAt)
		if tp.Contact != "" {
			fmt.Fprintf(ew, "Contact: %s\n", tp.Contact)
		}
		fmt.Fprintf(ew, "Open findings: %d (%d critical, %d high, %d medium)\n\n",
			tp.Summary.Total, tp.Summary.Critical, tp.Summary.High, tp.Summary.Medium)

		for j := range tp.Findings {
			f := &tp.Findings[j]
			fmt.Fprintf(ew, "[%d] %s\n", f.Rank, f.ControlID)
			if f.ControlName != "" {
				fmt.Fprintf(ew, "    %s\n", f.ControlName)
			}
			fmt.Fprintf(ew, "    Asset:    %s\n", f.AssetID)
			fmt.Fprintf(ew, "    Severity: %s\n", strings.ToUpper(f.Severity.String()))
			fmt.Fprintf(ew, "    Dwell:    %.0f hours\n", f.DwellHours)
			if f.SLABreached && f.OverdueHours != nil {
				fmt.Fprintf(ew, "    SLA:      BREACHED (%.0fh overdue)\n", *f.OverdueHours)
			}
			if f.RemediationAction != "" {
				fmt.Fprintf(ew, "    Fix:\n      %s\n", strings.TrimSpace(f.RemediationAction))
			}
			fmt.Fprintln(ew)
		}
	}
	return ew.err
}

func sevHeading(sev string) string {
	switch sev {
	case "critical":
		return "Critical Findings (Action Required Immediately)"
	case "high":
		return "High Findings (Remediate Within SLA Deadline)"
	case "medium":
		return "Medium Findings (Remediate Within SLA Deadline)"
	case "low":
		return "Low Findings"
	default:
		return strutil.TitleCase(sev) + " Findings"
	}
}

func hasCompliance(findings []PlanFinding) bool {
	for i := range findings {
		if len(findings[i].Compliance) > 0 {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// WriteCSV writes the plan as CSV — one row per finding, suitable for
// bulk import into Jira, ServiceNow, GitHub Issues, or Linear.
func WriteCSV(w io.Writer, p *Plan) error {
	cw := csv.NewWriter(w)
	header := []string{
		"team", "control_id", "control_name", "severity", "asset_id",
		"dwell_hours", "sla_deadline_hours", "sla_status",
		"remediation_command", "assignee_contact",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for i := range p.Teams {
		tp := &p.Teams[i]
		for j := range tp.Findings {
			f := &tp.Findings[j]
			slaStatus := "within_sla"
			if f.SLABreached && f.OverdueHours != nil {
				slaStatus = "breached"
			}
			dlh := ""
			if f.SLADeadlineHours != nil {
				dlh = fmt.Sprintf("%.0f", *f.SLADeadlineHours)
			}
			row := []string{
				tp.TeamName,
				f.ControlID,
				f.ControlName,
				strings.ToUpper(f.Severity.String()),
				f.AssetID,
				fmt.Sprintf("%.0f", f.DwellHours),
				dlh,
				slaStatus,
				strings.TrimSpace(f.RemediationAction),
				tp.Contact,
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

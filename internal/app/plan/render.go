package plan

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/util/strutil"
)

// WriteMarkdown writes the plan as a markdown document.
func WriteMarkdown(w io.Writer, p *Plan) {
	for i := range p.Teams {
		if i > 0 {
			_, _ = fmt.Fprint(w, "\n---\n\n")
		}
		writeTeamMarkdown(w, &p.Teams[i], p)
	}

	if len(p.Unattributed) > 0 {
		_, _ = fmt.Fprint(w, "\n---\n\n")
		fmt.Fprintln(w, "## Unattributed Findings")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "These findings could not be attributed to any team. Update team-manifest.yaml to assign ownership.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Control | Asset | Severity |")
		fmt.Fprintln(w, "|---------|-------|----------|")
		for i := range p.Unattributed {
			f := &p.Unattributed[i]
			fmt.Fprintf(w, "| %s | %s | %s |\n", f.ControlID, truncate(f.AssetID, 40), strings.ToUpper(f.Severity))
		}
	}
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
		sev := strings.ToLower(tp.Findings[i].Severity)
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
	fmt.Fprintf(w, "| Severity | %s |\n", strings.ToUpper(f.Severity))
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

// WriteText writes the plan in plain text format.
func WriteText(w io.Writer, p *Plan) {
	for i := range p.Teams {
		tp := &p.Teams[i]
		name := tp.TeamName
		if name == "" {
			name = tp.TeamID
		}
		fmt.Fprintf(w, "REMEDIATION PLAN — %s\n", strings.ToUpper(name))
		fmt.Fprintf(w, "Generated: %s\n", p.GeneratedAt)
		if tp.Contact != "" {
			fmt.Fprintf(w, "Contact: %s\n", tp.Contact)
		}
		fmt.Fprintf(w, "Open findings: %d (%d critical, %d high, %d medium)\n\n",
			tp.Summary.Total, tp.Summary.Critical, tp.Summary.High, tp.Summary.Medium)

		for j := range tp.Findings {
			f := &tp.Findings[j]
			fmt.Fprintf(w, "[%d] %s\n", f.Rank, f.ControlID)
			if f.ControlName != "" {
				fmt.Fprintf(w, "    %s\n", f.ControlName)
			}
			fmt.Fprintf(w, "    Asset:    %s\n", f.AssetID)
			fmt.Fprintf(w, "    Severity: %s\n", strings.ToUpper(f.Severity))
			fmt.Fprintf(w, "    Dwell:    %.0f hours\n", f.DwellHours)
			if f.SLABreached && f.OverdueHours != nil {
				fmt.Fprintf(w, "    SLA:      BREACHED (%.0fh overdue)\n", *f.OverdueHours)
			}
			if f.RemediationAction != "" {
				fmt.Fprintf(w, "    Fix:\n      %s\n", strings.TrimSpace(f.RemediationAction))
			}
			fmt.Fprintln(w)
		}
	}
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
			if f.SLABreached {
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
				strings.ToUpper(f.Severity),
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

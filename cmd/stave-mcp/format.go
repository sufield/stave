package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// formatVerify renders an Assessment as agent-friendly text. The
// detailed flag appends per-finding evidence (predicate, observed
// values, remediation) and the full chain list to the summary.
//
// This is presentation logic — it lives here, not in pkg/stave,
// because it shapes output for the MCP agent specifically. The
// underlying evaluation is unchanged.
//
// Verdict model (kept honest to the engine): every finding IS a
// violation, and any violation makes the snapshot NON_COMPLIANT.
// AT_RISK is a snapshot-level state — zero violations but an
// approaching-threshold risk signal — not a per-finding category, so
// we do not split findings into NON_COMPLIANT/AT_RISK buckets. We
// report the authoritative overall state, the severity breakdown, and
// the SLA-breach sub-count (violations past their max-unsafe window).
func formatVerify(a *stave.Assessment, score *stave.ScoreResult, detailed bool) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Security State: %s\n", a.Status)
	if score != nil {
		fmt.Fprintf(&b, "Posture Score:  %d/100 (%s)\n", score.ScoreInt, score.RubricBand)
	}

	fmt.Fprintf(&b, "\nViolations: %d across %d assets\n", a.Summary.Violations, a.Summary.TotalAssets)
	fmt.Fprintf(&b, "  By severity:   %s\n", severityLine(a.CountBySeverity()))
	fmt.Fprintf(&b, "  SLA breaches:  %d (violations past their max-unsafe window)\n", a.SLABreaches)

	ranked := rankBySeverity(a.Findings)
	if len(ranked) > 0 {
		fmt.Fprintf(&b, "\nTop findings by severity:\n")
		for i := range ranked {
			if i >= 10 {
				break
			}
			f := &ranked[i]
			fmt.Fprintf(&b, "  %d. [%s] %s — %s: %s\n",
				i+1, f.Severity, f.ControlID, f.AssetID, findingMessage(f))
		}
	}

	fmt.Fprintf(&b, "\nChain findings: %d\n", len(a.ChainFindings))
	for i := range a.ChainFindings {
		if i >= 3 {
			break
		}
		c := &a.ChainFindings[i]
		fmt.Fprintf(&b, "  - %s [%s]: %s (%d failing controls)\n",
			c.ChainID, c.Severity, c.Description, len(c.ControlsFailing))
	}

	fmt.Fprintf(&b, "\nEvaluated: %s | Snapshots: %d | Assets: %d\n",
		a.Run.Now.Format("2006-01-02T15:04:05Z07:00"), a.Run.Snapshots, a.Summary.TotalAssets)

	if !detailed {
		return b.String()
	}

	// Detailed: full evidence for every violation, severity-ranked.
	b.WriteString("\n── Detailed violations ──\n")
	writeFindingDetails(&b, ranked)

	if len(a.ChainFindings) > 0 {
		b.WriteString("\nChain findings (full):\n")
		for i := range a.ChainFindings {
			c := &a.ChainFindings[i]
			fmt.Fprintf(&b, "  %s [%s]\n    %s\n    Failing controls: %s\n",
				c.ChainID, c.Severity, c.Description, joinControlIDs(c.ControlsFailing))
		}
	}
	return b.String()
}

// rankBySeverity returns findings sorted by severity (critical first),
// ties broken by control then asset ID for determinism.
func rankBySeverity(findings []stave.Finding) []stave.Finding {
	out := make([]stave.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].ControlID != out[j].ControlID {
			return out[i].ControlID < out[j].ControlID
		}
		return out[i].AssetID < out[j].AssetID
	})
	return out
}

func severityRank(s stave.Severity) int {
	switch s {
	case stave.SeverityCritical:
		return 4
	case stave.SeverityHigh:
		return 3
	case stave.SeverityMedium:
		return 2
	case stave.SeverityLow:
		return 1
	default:
		return 0
	}
}

// severityLine renders the per-severity counts in fixed order.
func severityLine(counts map[stave.Severity]int) string {
	order := []stave.Severity{stave.SeverityCritical, stave.SeverityHigh, stave.SeverityMedium, stave.SeverityLow}
	parts := make([]string, 0, len(order))
	for _, s := range order {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// findingMessage is the human label for a finding — the control name,
// falling back to its remediation summary when unnamed.
func findingMessage(f *stave.Finding) string {
	if f.ControlName != "" {
		return f.ControlName
	}
	return f.Remediation.Description
}

// writeFindingDetails appends full per-finding evidence: the
// predicate that fired, the observed values, and the catalog
// remediation. findings are assumed already severity-ranked.
func writeFindingDetails(b *strings.Builder, findings []stave.Finding) {
	for i := range findings {
		f := &findings[i]
		fmt.Fprintf(b, "\n  Control:  %s [%s]\n  Asset:    %s\n", f.ControlID, f.Severity, f.AssetID)
		if f.ControlName != "" {
			fmt.Fprintf(b, "  Name:     %s\n", f.ControlName)
		}
		for _, clause := range f.ReasoningTrace {
			fmt.Fprintf(b, "  Predicate: %s\n", clause.PredicateExpr)
		}
		for _, d := range f.Delta {
			fmt.Fprintf(b, "  Observed: %s = %s\n", d.PropertyPath, d.CurrentValue)
		}
		if f.Remediation.Description != "" {
			fmt.Fprintf(b, "  Fix:      %s\n", f.Remediation.Description)
		}
	}
}

func joinControlIDs(ids []stave.ControlID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

// Package metrics produces Prometheus text format metrics from
// assessment data for node_exporter textfile collector integration.
package metrics

import (
	"fmt"
	"io"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

var canonicalSeverities = []policy.Severity{
	policy.SeverityCritical,
	policy.SeverityHigh,
	policy.SeverityMedium,
	policy.SeverityLow,
}

// Input configures the metrics generation.
type Input struct {
	Assessment   *report.Assessment
	PostureScore float64
	TeamFindings map[string][]remediation.Finding // team ID → findings
}

// Write produces Prometheus text format metrics to w.
func Write(w io.Writer, in Input) {
	if w == nil {
		return
	}
	// Posture score.
	writeGauge(w, "stave_posture_score", "Current posture score (0-100)", in.PostureScore)

	if in.Assessment == nil {
		return
	}
	a := in.Assessment

	// Findings by severity.
	severityCounts := countBySeverity(a.Findings)
	writeComment(w, "stave_findings_total", "Number of findings by severity")
	for _, sev := range canonicalSeverities {
		fmt.Fprintf(w, "stave_findings_total{severity=%q} %d\n", sev.String(), severityCounts[sev])
	}
	fmt.Fprintln(w)

	// SLA burn rates.
	slaMetrics := computeSLAMetrics(a.Findings)
	hasSLAOutput := false
	for _, sev := range canonicalSeverities {
		if _, ok := slaMetrics[sev]; ok {
			hasSLAOutput = true
			break
		}
	}
	if hasSLAOutput {
		writeComment(w, "stave_sla_burn_rate", "SLA burn rate by severity (0-1)")
		for _, sev := range canonicalSeverities {
			if rate, ok := slaMetrics[sev]; ok {
				fmt.Fprintf(w, "stave_sla_burn_rate{severity=%q} %.2f\n", sev.String(), rate)
			}
		}
		fmt.Fprintln(w)
	}

	// Chain activations.
	if len(a.ChainFindings) > 0 {
		writeGauge(w, "stave_chain_active_total", "Number of active attack chains", float64(len(a.ChainFindings)))
		writeComment(w, "stave_chain_active", "Active chain by ID")
		for i := range a.ChainFindings {
			cf := &a.ChainFindings[i]
			fmt.Fprintf(w, "stave_chain_active{chain=%q,severity=%q,asset_id=%q,scope_id=%q} 1\n",
				cf.ChainID, cf.Severity.String(), cf.AssetID, cf.ScopeID)
		}
		fmt.Fprintln(w)
	}

	// Per-team metrics.
	if len(in.TeamFindings) > 0 {
		writeComment(w, "stave_team_findings_total", "Findings by team")
		teamIDs := make([]string, 0, len(in.TeamFindings))
		for id := range in.TeamFindings {
			teamIDs = append(teamIDs, id)
		}
		slices.Sort(teamIDs)
		for _, teamID := range teamIDs {
			findings := in.TeamFindings[teamID]
			fmt.Fprintf(w, "stave_team_findings_total{team=%q} %d\n", teamID, len(findings))
		}
		fmt.Fprintln(w)
	}
}

func countBySeverity(findings []remediation.Finding) map[policy.Severity]int {
	counts := make(map[policy.Severity]int)
	for i := range findings {
		sev := findings[i].ControlSeverity
		counts[sev]++
	}
	return counts
}

func computeSLAMetrics(findings []remediation.Finding) map[policy.Severity]float64 {
	stats := remediation.FindingSet(findings).SLABreachSummary()
	rates := make(map[policy.Severity]float64, len(stats.TotalBySeverity))
	for sName, total := range stats.TotalBySeverity {
		if total > 0 {
			sev, _ := policy.ParseSeverity(sName)
			rates[sev] = float64(stats.BreachedBySeverity[sName]) / float64(total)
		}
	}
	return rates
}

func writeGauge(w io.Writer, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %.1f\n\n", name, value)
}

func writeComment(w io.Writer, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
}

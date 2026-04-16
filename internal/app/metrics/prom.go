// Package metrics produces Prometheus text format metrics from
// assessment data for node_exporter textfile collector integration.
package metrics

import (
	"fmt"
	"io"
	"slices"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// Input configures the metrics generation.
type Input struct {
	Assessment   *report.Assessment
	PostureScore float64
	TeamFindings map[string][]remediation.Finding // team ID → findings
}

// Write produces Prometheus text format metrics to w.
func Write(w io.Writer, in Input) {
	a := in.Assessment

	// Posture score.
	writeGauge(w, "stave_posture_score", "Current posture score (0-100)", in.PostureScore)

	// Findings by severity.
	severityCounts := countBySeverity(a.Findings)
	writeComment(w, "stave_findings_total", "Number of findings by severity")
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		fmt.Fprintf(w, "stave_findings_total{severity=%q} %d\n", sev, severityCounts[sev])
	}
	fmt.Fprintln(w)

	// SLA burn rates.
	slaMetrics := computeSLAMetrics(a.Findings)
	if len(slaMetrics) > 0 {
		writeComment(w, "stave_sla_burn_rate", "SLA burn rate by severity (0-1)")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if rate, ok := slaMetrics[sev]; ok {
				fmt.Fprintf(w, "stave_sla_burn_rate{severity=%q} %.2f\n", sev, rate)
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
			fmt.Fprintf(w, "stave_chain_active{chain=%q,severity=%q} 1\n",
				cf.ChainID, cf.Severity.String())
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

func countBySeverity(findings []remediation.Finding) map[string]int {
	counts := make(map[string]int)
	for i := range findings {
		sev := findings[i].ControlSeverity.String()
		counts[sev]++
	}
	return counts
}

func computeSLAMetrics(findings []remediation.Finding) map[string]float64 {
	type slaAgg struct{ total, breached int }
	agg := make(map[string]*slaAgg)

	for i := range findings {
		f := &findings[i]
		if f.SLADeadlineHours == nil {
			continue
		}
		sev := f.ControlSeverity.String()
		a, ok := agg[sev]
		if !ok {
			a = &slaAgg{}
			agg[sev] = a
		}
		a.total++
		if f.SLABreached {
			a.breached++
		}
	}

	rates := make(map[string]float64, len(agg))
	for sev, a := range agg {
		if a.total > 0 {
			rates[sev] = float64(a.breached) / float64(a.total)
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

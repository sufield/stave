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

// PostureScore represents a 0-100 security posture score.
type PostureScore float64

// Float64 returns the underlying float64 value.
func (p PostureScore) Float64() float64 {
	return float64(p)
}

// IsPassing reports whether the posture score meets the specified threshold.
func (p PostureScore) IsPassing(threshold float64) bool {
	return float64(p) >= threshold
}

// PostureScoreFromViolations calculates a posture score from violations and total assets.
func PostureScoreFromViolations(violations, totalAssets int) PostureScore {
	if totalAssets <= 0 {
		return 100
	}
	score := (1.0 - float64(violations)/float64(totalAssets)) * 100
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return PostureScore(score)
}

// SeverityCounts maps policy severities to their occurrence counts.
type SeverityCounts map[policy.Severity]int

// Total returns the sum of counts across all severities.
func (sc SeverityCounts) Total() int {
	total := 0
	for _, count := range sc {
		total += count
	}
	return total
}

// ForSeverity returns the count for the given severity, or 0 if not present.
func (sc SeverityCounts) ForSeverity(sev policy.Severity) int {
	return sc[sev]
}

// Critical returns the count of critical findings.
func (sc SeverityCounts) Critical() int {
	return sc[policy.SeverityCritical]
}

// High returns the count of high findings.
func (sc SeverityCounts) High() int {
	return sc[policy.SeverityHigh]
}

// SLABurnRate represents a 0.0 to 1.0 SLA breach rate.
type SLABurnRate float64

// Float64 returns the underlying float64 rate.
func (r SLABurnRate) Float64() float64 {
	return float64(r)
}

// Percentage returns the SLA burn rate as a percentage (0.0 to 100.0).
func (r SLABurnRate) Percentage() float64 {
	return float64(r) * 100.0
}

// IsBreached reports whether there is any SLA breach (> 0).
func (r SLABurnRate) IsBreached() bool {
	return float64(r) > 0
}

// IsWarning reports whether the burn rate exceeds the given threshold.
func (r SLABurnRate) IsWarning(threshold float64) bool {
	return float64(r) >= threshold
}

// SLAMetrics maps policy severities to their respective SLA burn rates.
type SLAMetrics map[policy.Severity]SLABurnRate

// HasBreaches reports whether any severity has an active SLA breach.
func (m SLAMetrics) HasBreaches() bool {
	for _, rate := range m {
		if rate.IsBreached() {
			return true
		}
	}
	return false
}

// RateFor returns the burn rate for the given severity, or 0 if not present.
func (m SLAMetrics) RateFor(sev policy.Severity) SLABurnRate {
	return m[sev]
}

// Input configures the metrics generation.
type Input struct {
	Assessment   *report.Assessment
	PostureScore PostureScore
	TeamFindings map[string][]remediation.Finding // team ID → findings
}

// Write produces Prometheus text format metrics to w.
func Write(w io.Writer, in Input) {
	if w == nil {
		return
	}
	// Posture score.
	writeGauge(w, "stave_posture_score", "Current posture score (0-100)", in.PostureScore.Float64())

	if in.Assessment == nil {
		return
	}
	a := in.Assessment

	// Findings by severity.
	severityCounts := countBySeverity(a.Findings)
	writeComment(w, "stave_findings_total", "Number of findings by severity")
	for _, sev := range canonicalSeverities {
		fmt.Fprintf(w, "stave_findings_total{severity=%q} %d\n", sev.String(), severityCounts.ForSeverity(sev))
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
				fmt.Fprintf(w, "stave_sla_burn_rate{severity=%q} %.2f\n", sev.String(), rate.Float64())
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

func countBySeverity(findings []remediation.Finding) SeverityCounts {
	counts := make(SeverityCounts)
	for i := range findings {
		sev := findings[i].ControlSeverity
		counts[sev]++
	}
	return counts
}

func computeSLAMetrics(findings []remediation.Finding) SLAMetrics {
	stats := remediation.FindingSet(findings).SLABreachSummary()
	rates := make(SLAMetrics, len(stats.TotalBySeverity))
	for sName, total := range stats.TotalBySeverity {
		if total > 0 {
			sev, _ := policy.ParseSeverity(sName)
			rates[sev] = SLABurnRate(float64(stats.BreachedBySeverity[sName]) / float64(total))
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

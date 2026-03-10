package securityaudit

import (
	"slices"
	"sort"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Finding is one security-audit result entry.
type Finding struct {
	ID             string       `json:"id"`
	Pillar         Pillar       `json:"pillar"`
	Status         Status       `json:"status"`
	Severity       Severity     `json:"severity"`
	Title          string       `json:"title"`
	Details        string       `json:"details"`
	AuditorHint    string       `json:"auditor_hint,omitempty"`
	Recommendation string       `json:"recommendation,omitempty"`
	EvidenceRefs   []string     `json:"evidence_refs,omitempty"`
	ControlRefs    []ControlRef `json:"control_refs,omitempty"`
}

// Summary captures aggregate run state.
type Summary struct {
	Total             int              `json:"total"`
	Pass              int              `json:"pass"`
	Warn              int              `json:"warn"`
	Fail              int              `json:"fail"`
	BySeverity        map[Severity]int `json:"by_severity"`
	FailOn            Severity         `json:"fail_on"`
	GatedFindingCount int              `json:"gated_finding_count"`
	Gated             bool             `json:"gated"`
	VulnSourceUsed    string           `json:"vuln_source_used,omitempty"`
	EvidenceFreshness string           `json:"evidence_freshness,omitempty"`
}

// Report is the top-level security-audit report document.
type Report struct {
	SchemaVersion kernel.Schema `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	ToolVersion   string        `json:"tool_version"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
	EvidenceIndex []EvidenceRef `json:"evidence_index"`
	Controls      []ControlRef  `json:"controls"`
}

// RecomputeSummary rebuilds pass/fail counts and severity tallies.
func (r *Report) RecomputeSummary() {
	if r == nil {
		return
	}
	out := Summary{
		BySeverity:        map[Severity]int{},
		FailOn:            r.Summary.FailOn,
		VulnSourceUsed:    r.Summary.VulnSourceUsed,
		EvidenceFreshness: r.Summary.EvidenceFreshness,
	}
	for _, finding := range r.Findings {
		out.Total++
		switch finding.Status {
		case StatusPass:
			out.Pass++
		case StatusWarn:
			out.Warn++
		case StatusFail:
			out.Fail++
		}
		out.BySeverity[finding.Severity]++
		if finding.Status != StatusPass && AtOrAbove(finding.Severity, out.FailOn) {
			out.GatedFindingCount++
		}
	}
	out.Gated = out.GatedFindingCount > 0
	r.Summary = out
}

// FilterBySeverity returns a copy filtered to the provided severities.
func (r Report) FilterBySeverity(allowed []Severity) Report {
	if len(allowed) == 0 {
		r.RecomputeSummary()
		return r
	}
	allowMap := make(map[Severity]bool, len(allowed))
	for _, sev := range allowed {
		allowMap[sev] = true
	}

	filtered := make([]Finding, 0, len(r.Findings))
	for _, finding := range r.Findings {
		if allowMap[finding.Severity] {
			filtered = append(filtered, finding)
		}
	}
	r.Findings = filtered
	r.RecomputeSummary()
	return r
}

// Normalize sorts findings and controls for deterministic output.
func (r *Report) Normalize() {
	if r == nil {
		return
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
			return SeverityRank(a.Severity) > SeverityRank(b.Severity)
		}
		if a.Status != b.Status {
			return a.Status > b.Status
		}
		return a.ID < b.ID
	})
	sort.Slice(r.EvidenceIndex, func(i, j int) bool {
		return r.EvidenceIndex[i].ID < r.EvidenceIndex[j].ID
	})
	sort.Slice(r.Controls, func(i, j int) bool {
		a, b := r.Controls[i], r.Controls[j]
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		return a.Rationale < b.Rationale
	})
	for i := range r.Findings {
		sort.Slice(r.Findings[i].ControlRefs, func(a, b int) bool {
			ra, rb := r.Findings[i].ControlRefs[a], r.Findings[i].ControlRefs[b]
			if ra.Framework != rb.Framework {
				return ra.Framework < rb.Framework
			}
			return ra.ControlID < rb.ControlID
		})
		r.Findings[i].EvidenceRefs = slices.Clone(r.Findings[i].EvidenceRefs)
		sort.Strings(r.Findings[i].EvidenceRefs)
	}
	r.RecomputeSummary()
}

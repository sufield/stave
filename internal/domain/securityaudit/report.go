package securityaudit

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Finding represents a single entry in a security audit.
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

// Summary captures aggregate statistics for the audit run.
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

// Report is the root document for a security audit.
type Report struct {
	SchemaVersion kernel.Schema `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	ToolVersion   string        `json:"tool_version"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
	EvidenceIndex []EvidenceRef `json:"evidence_index"`
	Controls      []ControlRef  `json:"controls"`
}

// RecomputeSummary rebuilds all aggregate counts and gating status based on current findings.
func (r *Report) RecomputeSummary() {
	if r == nil {
		return
	}

	s := Summary{
		BySeverity:        make(map[Severity]int),
		FailOn:            r.Summary.FailOn,
		VulnSourceUsed:    r.Summary.VulnSourceUsed,
		EvidenceFreshness: r.Summary.EvidenceFreshness,
		Total:             len(r.Findings),
	}

	for _, f := range r.Findings {
		switch f.Status {
		case StatusPass:
			s.Pass++
		case StatusWarn:
			s.Warn++
		case StatusFail:
			s.Fail++
		}

		s.BySeverity[f.Severity]++

		if f.Status != StatusPass && AtOrAbove(f.Severity, s.FailOn) {
			s.GatedFindingCount++
		}
	}

	s.Gated = s.GatedFindingCount > 0
	r.Summary = s
}

// FilterBySeverity returns a copy of the report containing only findings matching the allowed severities.
func (r Report) FilterBySeverity(allowed []Severity) Report {
	if len(allowed) == 0 {
		return r
	}

	allowedSet := make(map[Severity]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}

	filtered := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if _, ok := allowedSet[f.Severity]; ok {
			filtered = append(filtered, f)
		}
	}

	r.Findings = filtered
	r.RecomputeSummary()
	return r
}

// Normalize ensures deterministic ordering of all slices within the report.
func (r *Report) Normalize() {
	if r == nil {
		return
	}

	// Sort Findings: Severity (highest first), then Status, then ID
	slices.SortFunc(r.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(SeverityRank(b.Severity), SeverityRank(a.Severity)),
			cmp.Compare(a.Status, b.Status),
			cmp.Compare(a.ID, b.ID),
		)
	})

	// Sort Evidence Index by ID
	slices.SortFunc(r.EvidenceIndex, func(a, b EvidenceRef) int {
		return cmp.Compare(a.ID, b.ID)
	})

	// Sort Controls: Framework, then ControlID, then Rationale
	slices.SortFunc(r.Controls, func(a, b ControlRef) int {
		return cmp.Or(
			cmp.Compare(a.Framework, b.Framework),
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.Rationale, b.Rationale),
		)
	})

	// Sort nested lists within each finding
	for i := range r.Findings {
		f := &r.Findings[i]

		slices.SortFunc(f.ControlRefs, func(a, b ControlRef) int {
			return cmp.Or(
				cmp.Compare(a.Framework, b.Framework),
				cmp.Compare(a.ControlID, b.ControlID),
			)
		})

		slices.Sort(f.EvidenceRefs)
	}

	r.RecomputeSummary()
}

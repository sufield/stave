package securityaudit

import (
	"cmp"
	"slices"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/outcome"
)

// Report is the root document for a security audit.
// It is designed to be deterministic and JSON-serializable.
type Report struct {
	SchemaVersion kernel.Schema `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	StaveVersion  string        `json:"tool_version"`
	Summary       Summary       `json:"summary"`
	Findings      []Finding     `json:"findings"`
	EvidenceIndex []EvidenceRef `json:"evidence_index"`
	Controls      []ControlRef  `json:"controls"`
}

// Finding represents a single entry in a security audit.
type Finding struct {
	ID             CheckID         `json:"id"`
	Pillar         Pillar          `json:"pillar"`
	Status         outcome.Status  `json:"status"`
	Severity       policy.Severity `json:"severity"`
	Title          string          `json:"title"`
	Details        string          `json:"details"`
	AuditorHint    string          `json:"auditor_hint,omitempty"`
	Recommendation string          `json:"recommendation,omitempty"`
	EvidenceRefs   []string        `json:"evidence_refs,omitempty"`
	ControlRefs    []ControlRef    `json:"control_refs,omitempty"`
}

// Summary captures aggregate statistics for the audit run.
type Summary struct {
	Total             int                     `json:"total"`
	Pass              int                     `json:"pass"`
	Warn              int                     `json:"warn"`
	Fail              int                     `json:"fail"`
	BySeverity        map[policy.Severity]int `json:"by_severity"`
	FailOn            policy.Severity         `json:"fail_on"`
	GatedFindingCount int                     `json:"gated_finding_count"`
	Gated             bool                    `json:"gated"`
	VulnSourceUsed    string                  `json:"vuln_source_used,omitempty"`
	EvidenceFreshness string                  `json:"evidence_freshness,omitempty"`
}

// RecomputeSummary rebuilds all aggregate counts and gating status from
// the current findings. Ensures the summary is consistent with the data.
func (r *Report) RecomputeSummary() {
	if r == nil {
		return
	}

	s := Summary{
		BySeverity:        make(map[policy.Severity]int),
		FailOn:            r.Summary.FailOn,
		VulnSourceUsed:    r.Summary.VulnSourceUsed,
		EvidenceFreshness: r.Summary.EvidenceFreshness,
		Total:             len(r.Findings),
	}

	for _, f := range r.Findings {
		switch f.Status {
		case outcome.Pass:
			s.Pass++
		case outcome.Warn:
			s.Warn++
		case outcome.Fail:
			s.Fail++
		}

		s.BySeverity[f.Severity]++

		// FailOn=None means "disable gating" — skip the check entirely.
		if s.FailOn != policy.SeverityNone && f.Status != outcome.Pass && f.Severity.Gte(s.FailOn) {
			s.GatedFindingCount++
		}
	}

	s.Gated = s.GatedFindingCount > 0
	r.Summary = s
}

// CloneWithFilter returns a new Report containing only findings that
// match the allowed severities. The summary is recomputed for the
// filtered set. Evidence and control references are cloned to ensure
// the new report is independent.
func (r *Report) CloneWithFilter(allowed []policy.Severity) *Report {
	if r == nil {
		return nil
	}
	if len(allowed) == 0 {
		cp := *r
		return &cp
	}

	allowedSet := make(map[policy.Severity]struct{}, len(allowed))
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}

	filtered := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if _, ok := allowedSet[f.Severity]; ok {
			filtered = append(filtered, f)
		}
	}

	newReport := &Report{
		SchemaVersion: r.SchemaVersion,
		GeneratedAt:   r.GeneratedAt,
		StaveVersion:  r.StaveVersion,
		Summary:       r.Summary,
		Findings:      filtered,
		EvidenceIndex: slices.Clone(r.EvidenceIndex),
		Controls:      slices.Clone(r.Controls),
	}
	newReport.RecomputeSummary()
	return newReport
}

// Normalize ensures deterministic ordering of all slices within the report.
// This is critical for generating consistent hashes and meaningful diffs
// between audit runs.
func (r *Report) Normalize() {
	if r == nil {
		return
	}

	slices.SortFunc(r.Findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(int(b.Severity), int(a.Severity)),
			cmp.Compare(a.Status, b.Status),
			cmp.Compare(a.ID, b.ID),
		)
	})

	slices.SortFunc(r.EvidenceIndex, func(a, b EvidenceRef) int {
		return cmp.Compare(a.ID, b.ID)
	})

	slices.SortFunc(r.Controls, func(a, b ControlRef) int {
		return cmp.Or(
			cmp.Compare(a.Framework, b.Framework),
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.Rationale, b.Rationale),
		)
	})

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

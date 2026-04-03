package securityaudit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	domain "github.com/sufield/stave/internal/core/securityaudit"
)

// --- JSON DTO types ---
// These mirror the domain types but use uppercase string severity for
// backward-compatible output.

type jsonReport struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	StaveVersion  string        `json:"tool_version"`
	Summary       jsonSummary   `json:"summary"`
	Findings      []jsonFinding `json:"findings"`
	EvidenceIndex []jsonEvRef   `json:"evidence_index"`
	Controls      []jsonCtlRef  `json:"controls"`
}

type jsonSummary struct {
	Total             int            `json:"total"`
	Pass              int            `json:"pass"`
	Warn              int            `json:"warn"`
	Fail              int            `json:"fail"`
	BySeverity        map[string]int `json:"by_severity"`
	FailOn            string         `json:"fail_on"`
	GatedFindingCount int            `json:"gated_finding_count"`
	Gated             bool           `json:"gated"`
	VulnSourceUsed    string         `json:"vuln_source_used,omitempty"`
	EvidenceFreshness string         `json:"evidence_freshness,omitempty"`
}

type jsonFinding struct {
	ID             string       `json:"id"`
	Pillar         string       `json:"pillar"`
	Status         string       `json:"status"`
	Severity       string       `json:"severity"`
	Title          string       `json:"title"`
	Details        string       `json:"details"`
	AuditorHint    string       `json:"auditor_hint,omitempty"`
	Recommendation string       `json:"recommendation,omitempty"`
	EvidenceRefs   []string     `json:"evidence_refs,omitempty"`
	ControlRefs    []jsonCtlRef `json:"control_refs,omitempty"`
}

type jsonEvRef struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Description string `json:"description,omitempty"`
}

type jsonCtlRef struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Rationale string `json:"rationale"`
}

// MarshalJSONReport renders the security-audit report as indented JSON.
// Severity values are rendered in UPPERCASE to preserve the original
// security-audit output contract.
func MarshalJSONReport(report domain.Report) ([]byte, error) {
	dto := toJSONReport(report)
	data, err := json.MarshalIndent(dto, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal security audit json: %w", err)
	}
	return append(data, '\n'), nil
}

func toJSONReport(r domain.Report) jsonReport {
	findings := make([]jsonFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = toJSONFinding(f)
	}
	evIndex := make([]jsonEvRef, len(r.EvidenceIndex))
	for i, e := range r.EvidenceIndex {
		evIndex[i] = jsonEvRef{
			ID:          e.ID,
			Path:        e.Path,
			SHA256:      e.SHA256,
			Description: e.Description,
		}
	}
	controls := make([]jsonCtlRef, len(r.Controls))
	for i, c := range r.Controls {
		controls[i] = jsonCtlRef{
			Framework: c.Framework,
			ControlID: c.ControlID,
			Rationale: c.Rationale,
		}
	}
	return jsonReport{
		SchemaVersion: string(r.SchemaVersion),
		GeneratedAt:   r.GeneratedAt,
		StaveVersion:  r.StaveVersion,
		Summary:       toJSONSummary(r.Summary),
		Findings:      findings,
		EvidenceIndex: evIndex,
		Controls:      controls,
	}
}

func toJSONSummary(s domain.Summary) jsonSummary {
	bySev := make(map[string]int, len(s.BySeverity))
	for k, v := range s.BySeverity {
		bySev[strings.ToUpper(k.String())] = v
	}
	return jsonSummary{
		Total:             s.Total,
		Pass:              s.Pass,
		Warn:              s.Warn,
		Fail:              s.Fail,
		BySeverity:        bySev,
		FailOn:            strings.ToUpper(s.FailOn.String()),
		GatedFindingCount: s.GatedFindingCount,
		Gated:             s.Gated,
		VulnSourceUsed:    s.VulnSourceUsed,
		EvidenceFreshness: s.EvidenceFreshness,
	}
}

func toJSONFinding(f domain.Finding) jsonFinding {
	controlRefs := make([]jsonCtlRef, len(f.ControlRefs))
	for i, c := range f.ControlRefs {
		controlRefs[i] = jsonCtlRef{
			Framework: c.Framework,
			ControlID: c.ControlID,
			Rationale: c.Rationale,
		}
	}
	return jsonFinding{
		ID:             string(f.ID),
		Pillar:         string(f.Pillar),
		Status:         f.Status.String(),
		Severity:       strings.ToUpper(f.Severity.String()),
		Title:          f.Title,
		Details:        f.Details,
		AuditorHint:    f.AuditorHint,
		Recommendation: f.Recommendation,
		EvidenceRefs:   f.EvidenceRefs,
		ControlRefs:    controlRefs,
	}
}

// Package compliance implements the compliance evidence export subcommand.
package compliance

import (
	"strings"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evidence"
)

// EvidenceExport is the top-level JSON document produced by the compliance export.
type EvidenceExport struct {
	ExportedAt      time.Time              `json:"exported_at"`
	StaveVersion    string                 `json:"stave_version"`
	SnapshotID      string                 `json:"snapshot_id"`
	SnapshotTakenAt time.Time              `json:"snapshot_taken_at"`
	Profile         ProfileSummary         `json:"profile"`
	Score           ScoreExport            `json:"score"`
	Requirements    []RequirementExport    `json:"requirements"`
	Evidence        []EvidenceRecordExport `json:"evidence"`
}

// ProfileSummary is the profile metadata in the JSON output.
type ProfileSummary struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScoreExport is the aggregate compliance score.
type ScoreExport struct {
	RequirementsTotal   int     `json:"requirements_total"`
	RequirementsMet     int     `json:"requirements_met"`
	RequirementsNotMet  int     `json:"requirements_not_met"`
	RequirementsNotEval int     `json:"requirements_not_evaluated"`
	RequirementsIncomp  int     `json:"requirements_incomplete"`
	OverallPercent      float64 `json:"overall_percent"`
}

// RequirementExport is a single requirement in the JSON output.
type RequirementExport struct {
	ID            string            `json:"id"`
	Description   string            `json:"description"`
	Section       string            `json:"section"`
	Status        RequirementStatus `json:"status"`
	Controls      []ControlSummary  `json:"controls"`
	Gaps          []GapExport       `json:"gaps,omitempty"`
	SLACompliance *SLACompliance    `json:"sla_compliance,omitempty"`
}

// RequirementStatus is the wire-format string a requirement carries
// in compliance JSON / markdown / table output. Values match the
// vocabulary the evidence-profile evaluator emits ("met", "not_met",
// "not_evaluated", "incomplete"). Label / Icon methods replace the
// per-renderer switch statements that used to do the same mapping.
type RequirementStatus string

// Recognised RequirementStatus values.
const (
	RequirementStatusMet          RequirementStatus = "met"
	RequirementStatusNotMet       RequirementStatus = "not_met"
	RequirementStatusNotEvaluated RequirementStatus = "not_evaluated"
	RequirementStatusIncomplete   RequirementStatus = "incomplete"
)

// Label returns the uppercase human-readable label compliance text
// renderers print for this status. Replaces the standalone
// statusLabel function that used to live in render_table.
func (s RequirementStatus) Label() string {
	switch s {
	case RequirementStatusMet:
		return "SATISFIED"
	case RequirementStatusNotMet:
		return "NOT MET"
	case RequirementStatusNotEvaluated:
		return "NOT EVAL"
	case RequirementStatusIncomplete:
		return "INCOMPLETE"
	default:
		return strings.ToUpper(string(s))
	}
}

// Icon returns the markdown-friendly label compliance markdown
// renderers print. Currently identical to Label for recognised
// values and the raw string otherwise; kept as a separate method
// so a future markdown-only emoji / glyph addition lands once.
func (s RequirementStatus) Icon() string {
	switch s {
	case RequirementStatusMet:
		return "SATISFIED"
	case RequirementStatusNotMet:
		return "NOT MET"
	case RequirementStatusNotEvaluated:
		return "NOT EVAL"
	case RequirementStatusIncomplete:
		return "INCOMPLETE"
	default:
		return string(s)
	}
}

// SLACompliance holds per-requirement SLA metrics. Present only when
// an SLA profile was active during assessment.
type SLACompliance struct {
	FindingsDetected    int     `json:"findings_detected"`
	FindingsWithinSLA   int     `json:"findings_within_sla"`
	FindingsBreachedSLA int     `json:"findings_breached_sla"`
	CompliancePercent   float64 `json:"compliance_rate_percent"`
	LongestOverdueHours float64 `json:"longest_overdue_hours"`
}

// ControlSummary shows pass/fail/incomplete counts per control.
type ControlSummary struct {
	ID              string `json:"id"`
	PassCount       int    `json:"pass_count"`
	FailCount       int    `json:"fail_count"`
	IncompleteCount int    `json:"incomplete_count"`
}

// IsPassing reports whether this control summary records zero
// failures and zero incomplete evaluations — the gate the table
// renderer uses to count "passing" controls. Replaces the inline
// (FailCount == 0 && IncompleteCount == 0) probe.
func (cs *ControlSummary) IsPassing() bool {
	return cs != nil && cs.FailCount == 0 && cs.IncompleteCount == 0
}

// Add increments the appropriate counter on this summary based on
// rec's verdict. Centralises the (verdict → counter) mapping so the
// buildExport loop stops switching on rec.Verdict at the call site.
// nil rec is a no-op.
func (cs *ControlSummary) Add(rec *evidence.EvidenceRecord) {
	if cs == nil || rec == nil {
		return
	}
	switch {
	case rec.IsPass():
		cs.PassCount++
	case rec.IsFail():
		cs.FailCount++
	case rec.IsIncomplete():
		cs.IncompleteCount++
	}
}

// GapExport identifies a specific compliance gap.
type GapExport struct {
	ControlID   string `json:"control_id"`
	ResourceARN string `json:"resource_arn"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
}

// EvidenceRecordExport is a single evidence record in the JSON output.
type EvidenceRecordExport struct {
	ControlID      string        `json:"control_id"`
	ControlName    string        `json:"control_name"`
	ResourceARN    string        `json:"resource_arn"`
	Verdict        string        `json:"verdict"`
	Severity       string        `json:"severity"`
	Citations      []CitationExp `json:"citations"`
	ReasoningTrace TraceExport   `json:"reasoning_trace"`
	EvaluatedAt    time.Time     `json:"evaluated_at"`
}

// CitationExp is a regulatory citation reference.
type CitationExp struct {
	Framework   string `json:"framework"`
	Requirement string `json:"requirement"`
}

// TraceExport is the reasoning trace for an evidence record.
type TraceExport struct {
	InvariantEvaluated string           `json:"invariant_evaluated"`
	FailCondition      string           `json:"fail_condition,omitempty"`
	FindingMessage     string           `json:"finding_message"`
	Observations       []ObservationExp `json:"observation_properties,omitempty"`
}

// ObservationExp is a single observed property value.
type ObservationExp struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// buildExport converts domain types to the serialisable EvidenceExport.
// findings may be nil — when present, SLA compliance data is computed
// per requirement from the finding-level SLA annotations.
func buildExport(
	profile *evidence.FrameworkProfile,
	assessment *evidence.ProfileAssessment,
	pkg *evidence.EvidencePackage,
	staveVersion string,
	snapshotTakenAt time.Time,
	includePasses bool,
	minSeverity string,
	findings []evaluation.Finding,
) *EvidenceExport {
	export := &EvidenceExport{
		ExportedAt:      time.Now().UTC(),
		StaveVersion:    staveVersion,
		SnapshotID:      pkg.SnapshotID,
		SnapshotTakenAt: snapshotTakenAt,
		Profile: ProfileSummary{
			ID:      profile.ID,
			Name:    profile.Name,
			Version: profile.Version,
		},
		Score: ScoreExport{
			RequirementsTotal:   assessment.TotalRequirements,
			RequirementsMet:     assessment.MetCount,
			RequirementsNotMet:  assessment.NotMetCount,
			RequirementsNotEval: assessment.NotEvaluatedCount,
			RequirementsIncomp:  assessment.IncompleteCount,
			OverallPercent:      assessment.CoveragePercent,
		},
	}

	// Build requirements
	for i := range assessment.Requirements {
		ra := &assessment.Requirements[i]
		re := RequirementExport{
			ID:          ra.RequirementID,
			Description: ra.Description,
			Section:     ra.Section,
			Status:      RequirementStatus(ra.Status.String()),
		}

		// Build per-control summaries from evidence records
		ctlCounts := make(map[string]*ControlSummary)
		for _, rec := range ra.Evidence {
			cs, ok := ctlCounts[rec.ControlID]
			if !ok {
				cs = &ControlSummary{ID: rec.ControlID}
				ctlCounts[rec.ControlID] = cs
			}
			cs.Add(rec)
		}
		for _, cs := range ctlCounts {
			re.Controls = append(re.Controls, *cs)
		}

		// Build gaps from failing/incomplete evidence
		for _, rec := range ra.Evidence {
			if rec.IsGap() {
				re.Gaps = append(re.Gaps, GapExport{
					ControlID:   rec.ControlID,
					ResourceARN: rec.ResourceARN,
					Severity:    rec.Severity,
					Message:     rec.ReasoningTrace.FindingMessage,
				})
			}
		}

		// Compute SLA compliance for this requirement from findings.
		if sla := computeRequirementSLA(ra, findings, profile.FrameworkKey); sla != nil {
			re.SLACompliance = sla
		}

		export.Requirements = append(export.Requirements, re)
	}

	// Build filtered evidence records
	for _, rec := range pkg.Records {
		if !includePasses && rec.Verdict == evidence.VerdictPass {
			continue
		}
		if !matchesSeverity(rec.Severity, minSeverity) {
			continue
		}

		er := EvidenceRecordExport{
			ControlID:   rec.ControlID,
			ControlName: rec.ControlName,
			ResourceARN: rec.ResourceARN,
			Verdict:     rec.Verdict.String(),
			Severity:    rec.Severity,
			EvaluatedAt: rec.EvaluatedAt,
			ReasoningTrace: TraceExport{
				InvariantEvaluated: rec.ReasoningTrace.InvariantEvaluated,
				FailCondition:      rec.ReasoningTrace.FailCondition,
				FindingMessage:     rec.ReasoningTrace.FindingMessage,
			},
		}
		for _, c := range rec.Citations {
			er.Citations = append(er.Citations, CitationExp{
				Framework:   c.Framework,
				Requirement: c.Requirement,
			})
		}
		for _, o := range rec.ReasoningTrace.ObservationProperties {
			er.ReasoningTrace.Observations = append(er.ReasoningTrace.Observations, ObservationExp{
				Field: o.Field,
				Value: o.Value,
			})
		}
		export.Evidence = append(export.Evidence, er)
	}

	return export
}

// computeRequirementSLA builds SLA compliance data for a requirement from
// the assessment findings. Returns nil when no findings have SLA data.
func computeRequirementSLA(ra *evidence.RequirementAssessment, findings []evaluation.Finding, framework string) *SLACompliance {
	if len(findings) == 0 {
		return nil
	}

	// Build set of control IDs mapped to this requirement via evidence records.
	reqControlIDs := make(map[string]bool)
	for _, rec := range ra.Evidence {
		reqControlIDs[rec.ControlID] = true
	}

	var detected, withinSLA, breached int
	var longestOverdue float64
	hasSLA := false

	for i := range findings {
		f := &findings[i]
		if !reqControlIDs[string(f.ControlID)] {
			continue
		}
		// Only count findings that have compliance mapping for this framework.
		if _, ok := f.ControlCompliance[policy.ComplianceFramework(framework)]; !ok {
			continue
		}
		if !f.HasSLA() {
			continue
		}
		hasSLA = true
		detected++
		if f.IsOverdue() {
			breached++
			if hours, ok := f.OverdueHours(); ok && hours > longestOverdue {
				longestOverdue = hours
			}
		} else {
			withinSLA++
		}
	}

	if !hasSLA {
		return nil
	}

	var pct float64
	if detected > 0 {
		pct = float64(withinSLA) / float64(detected) * 100
	}

	return &SLACompliance{
		FindingsDetected:    detected,
		FindingsWithinSLA:   withinSLA,
		FindingsBreachedSLA: breached,
		CompliancePercent:   pct,
		LongestOverdueHours: longestOverdue,
	}
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// matchesSeverity returns true if the record severity meets the minimum threshold.
func matchesSeverity(recordSeverity, minSeverity string) bool {
	if minSeverity == "" || minSeverity == "all" {
		return true
	}
	return severityRank(recordSeverity) >= severityRank(minSeverity)
}

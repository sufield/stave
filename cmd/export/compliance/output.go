// Package compliance implements the compliance evidence export subcommand.
package compliance

import (
	"time"

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
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Section     string           `json:"section"`
	Status      string           `json:"status"`
	Controls    []ControlSummary `json:"controls"`
	Gaps        []GapExport      `json:"gaps,omitempty"`
}

// ControlSummary shows pass/fail/incomplete counts per control.
type ControlSummary struct {
	ID              string `json:"id"`
	PassCount       int    `json:"pass_count"`
	FailCount       int    `json:"fail_count"`
	IncompleteCount int    `json:"incomplete_count"`
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
func buildExport(
	profile *evidence.FrameworkProfile,
	assessment *evidence.ProfileAssessment,
	pkg *evidence.EvidencePackage,
	staveVersion string,
	snapshotTakenAt time.Time,
	includePasses bool,
	minSeverity string,
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
			Status:      ra.Status.String(),
		}

		// Build per-control summaries from evidence records
		ctlCounts := make(map[string]*ControlSummary)
		for _, rec := range ra.Evidence {
			cs, ok := ctlCounts[rec.ControlID]
			if !ok {
				cs = &ControlSummary{ID: rec.ControlID}
				ctlCounts[rec.ControlID] = cs
			}
			switch rec.Verdict {
			case evidence.VerdictPass:
				cs.PassCount++
			case evidence.VerdictFail:
				cs.FailCount++
			case evidence.VerdictIncomplete:
				cs.IncompleteCount++
			}
		}
		for _, cs := range ctlCounts {
			re.Controls = append(re.Controls, *cs)
		}

		// Build gaps from failing/incomplete evidence
		for _, rec := range ra.Evidence {
			if rec.Verdict == evidence.VerdictFail || rec.Verdict == evidence.VerdictIncomplete {
				re.Gaps = append(re.Gaps, GapExport{
					ControlID:   rec.ControlID,
					ResourceARN: rec.ResourceARN,
					Severity:    rec.Severity,
					Message:     rec.ReasoningTrace.FindingMessage,
				})
			}
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

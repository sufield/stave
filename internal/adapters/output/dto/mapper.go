package dto

import (
	"errors"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// FromEvaluation projects a report.Assessment into a ResultDTO.
// Returns an error when e is nil so callers surface the upstream
// pipeline failure instead of producing empty-but-valid JSON.
func FromEvaluation(e *report.Assessment) (ResultDTO, error) {
	if e == nil {
		return ResultDTO{}, errors.New("dto: nil assessment")
	}
	return ResultDTO{
		SchemaVersion:     e.SchemaVersion,
		Kind:              string(e.Kind),
		Run:               NewRunInfoDTO(e.Run),
		Summary:           NewSummaryDTO(e.Summary),
		SecurityState:     e.Status,
		RiskSignals:       fromAtRiskItems(e.RiskSignals),
		Findings:          fromFindings(e.Findings),
		Indeterminate:     fromIndeterminateFindings(e.IndeterminateFindings),
		MarkerFindings:    fromFindings(e.MarkerFindings),
		ChainFindings:     fromCompoundFindings(e.ChainFindings, e.Findings),
		NearMissChains:    fromNearMissChains(e.NearMissChains),
		Issues:            fromIssues(e.Issues),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		SkippedControls:   fromSkippedControls(e.SkippedControls),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
		TopExposures:      fromExposureRanks(e.TopExposures),
		CoveragePosture:   FromCoverageIndex(e.CoveragePosture),
		Extensions:        NewExtensionsDTO(e.Extensions),
	}, nil
}

// fromIndeterminateFindings converts remediation.Finding values whose
// misconfigurations are all field-absent into IndeterminateDTO.
func fromIndeterminateFindings(fs []remediation.Finding) []IndeterminateDTO {
	if len(fs) == 0 {
		return nil
	}
	out := make([]IndeterminateDTO, len(fs))
	for i := range fs {
		f := &fs[i]
		out[i] = IndeterminateDTO{
			ControlID:     string(f.ControlID),
			ControlName:   f.ControlName,
			Severity:      f.ControlSeverity.String(),
			AssetID:       string(f.AssetID),
			AssetType:     string(f.AssetType),
			Verdict:       "INDETERMINATE",
			MissingFields: f.MissingFields(),
			GapCause:      classifyGapCause(f.MissingFields()),
		}
	}
	return out
}

// classifyGapCause infers the gap cause from the missing field paths.
// Fields containing "tag" or prefixed with a custom tag namespace
// (e.g. "stave:") are tag gaps. Everything else defaults to collector gap.
func classifyGapCause(fields []string) string {
	for _, f := range fields {
		if strings.Contains(f, "tag") || strings.Contains(f, "stave:") || strings.Contains(f, "intent") {
			return "tag_gap"
		}
	}
	return "collector_gap"
}

// fromIssues converts evaluation.Issue values into the DTO shape.
func fromIssues(is []evaluation.Issue) []IssueDTO {
	if len(is) == 0 {
		return nil
	}
	out := make([]IssueDTO, len(is))
	for i, iss := range is {
		out[i] = IssueDTO{
			IssueID:                 string(iss.IssueID),
			AssetID:                 string(iss.AssetID),
			SharedKeys:              iss.SharedKeyStrings(),
			HeadlineFindingID:       string(iss.HeadlineFindingID),
			MemberFindingIDs:        iss.MemberFindingIDStrings(),
			ConsolidatedScore:       iss.ConsolidatedScore.Value(),
			ConsolidatedBlastRadius: iss.ConsolidatedBlastRadius.Value(),
		}
	}
	return out
}

func mapSlice[T, U any](s []T, f func(T) U) []U {
	if s == nil {
		return nil
	}
	out := make([]U, len(s))
	for i, v := range s {
		out[i] = f(v)
	}
	return out
}

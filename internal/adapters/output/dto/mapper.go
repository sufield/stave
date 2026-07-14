package dto

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
)

// FromEvaluation projects a report.Assessment into a ResultDTO.
// Returns the zero ResultDTO when e is nil rather than panicking on
// e.SchemaVersion — the public marshaller calls this directly and
// upstream callers may still hold a nil result during error paths.
func FromEvaluation(e *report.Assessment) ResultDTO {
	if e == nil {
		return ResultDTO{}
	}
	return ResultDTO{
		SchemaVersion:     e.SchemaVersion,
		Kind:              string(e.Kind),
		Run:               NewRunInfoDTO(e.Run),
		Summary:           NewSummaryDTO(e.Summary),
		SecurityState:     e.Status,
		RiskSignals:       fromAtRiskItems(e.RiskSignals),
		Findings:          fromFindings(e.Findings),
		MarkerFindings:    fromFindings(e.MarkerFindings),
		ChainFindings:     fromCompoundFindings(e.ChainFindings),
		NearMissChains:    fromNearMissChains(e.NearMissChains),
		Issues:            fromIssues(e.Issues),
		ExceptedFindings:  fromExceptedFindings(e.ExceptedFindings),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		SkippedControls:   fromSkippedControls(e.SkippedControls),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
		TopExposures:      fromExposureRanks(e.TopExposures),
		CoveragePosture:   FromCoverageIndex(e.CoveragePosture),
		Extensions:        NewExtensionsDTO(e.Extensions),
	}
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

package dto

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
)

// FromEvaluation projects a report.Assessment into a ResultDTO.
func FromEvaluation(e *report.Assessment) ResultDTO {
	return ResultDTO{
		SchemaVersion:     e.SchemaVersion,
		Kind:              string(e.Kind),
		Run:               fromRunInfo(e.Run),
		Summary:           fromSummary(e.Summary),
		SecurityState:     e.Status,
		RiskSignals:       fromAtRiskItems(e.RiskSignals),
		Findings:          fromFindings(e.Findings),
		Issues:            fromIssues(e.Issues),
		ExceptedFindings:  fromExceptedFindings(e.ExceptedFindings),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		SkippedControls:   fromSkippedControls(e.SkippedControls),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
		TopExposures:      e.TopExposures,
		Extensions:        fromExtensions(e.Extensions),
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
			IssueID:                 iss.IssueID,
			AssetID:                 string(iss.AssetID),
			SharedKeys:              iss.SharedKeys,
			HeadlineFindingID:       iss.HeadlineFindingID,
			MemberFindingIDs:        iss.MemberFindingIDs,
			ConsolidatedScore:       iss.ConsolidatedScore,
			ConsolidatedBlastRadius: iss.ConsolidatedBlastRadius,
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

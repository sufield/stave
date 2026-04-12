package dto

import (
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
		ExceptedFindings:  fromExceptedFindings(e.ExceptedFindings),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		SkippedControls:   fromSkippedControls(e.SkippedControls),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
		TopExposures:      e.TopExposures,
		Extensions:        fromExtensions(e.Extensions),
	}
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

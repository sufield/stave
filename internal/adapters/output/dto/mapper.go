package dto

import (
	"github.com/sufield/stave/internal/safetyenvelope"
)

// FromEvaluation projects a safetyenvelope.Evaluation into a ResultDTO.
func FromEvaluation(e *safetyenvelope.Evaluation) ResultDTO {
	return ResultDTO{
		SchemaVersion:     e.SchemaVersion,
		Kind:              string(e.Kind),
		Run:               fromRunInfo(e.Run),
		Summary:           fromSummary(e.Summary),
		SafetyStatus:      e.SafetyStatus,
		AtRisk:            fromAtRiskItems(e.AtRisk),
		Findings:          fromFindings(e.Findings),
		ExceptedFindings:  fromExceptedFindings(e.ExceptedFindings),
		RemediationGroups: fromRemediationGroups(e.RemediationGroups),
		Skipped:           fromSkippedControls(e.Skipped),
		ExemptedAssets:    fromExemptedAssets(e.ExemptedAssets),
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

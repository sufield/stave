package shared

import (
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
)

// BaselineComparison holds the result of comparing baseline to current findings.
type BaselineComparison struct {
	Baseline   []evaluation.BaselineEntry
	Current    []evaluation.BaselineEntry
	Comparison evaluation.BaselineComparisonResult
}

// CompareBaseline converts current findings to baseline entries and compares
// them against baseline entries. Callers that need sanitization should apply it
// to the returned Current/Comparison entries after the call.
func CompareBaseline(
	baseEntries []evaluation.BaselineEntry,
	currentFindings []remediation.Finding,
) BaselineComparison {
	current := remediation.BaselineEntriesFromFindings(currentFindings)
	comparison := evaluation.CompareBaseline(baseEntries, current)
	return BaselineComparison{
		Baseline:   baseEntries,
		Current:    current,
		Comparison: comparison,
	}
}

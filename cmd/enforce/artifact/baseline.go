package artifact

import (
	output "github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// BaselineComparisonResult holds the full context of a comparison between
// a known baseline and the current findings.
type BaselineComparisonResult struct {
	Baseline   []evaluation.BaselineEntry
	Current    []evaluation.BaselineEntry
	Comparison evaluation.BaselineComparisonResult
}

// CompareAgainstBaseline transforms current findings into baseline entries
// and executes a domain-level comparison.
//
// If a sanitizer is provided, it is applied to the current findings before
// comparison to ensure that entries in the result respect anonymization settings.
func CompareAgainstBaseline(
	san kernel.Sanitizer,
	baseEntries []evaluation.BaselineEntry,
	currentFindings []remediation.Finding,
) BaselineComparisonResult {
	current := remediation.BaselineEntriesFromFindings(currentFindings)
	current = output.SanitizeBaselineEntries(san, current)
	comparison := evaluation.CompareBaseline(baseEntries, current)
	return BaselineComparisonResult{
		Baseline:   baseEntries,
		Current:    current,
		Comparison: comparison,
	}
}

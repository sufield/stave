package remediationimpact

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_ComputeSimpleScore_ZeroAssetsWithViolations(t *testing.T) {
	// An assessment report with 0 TotalAssets but 5 Violations.
	// Historically, computeSimpleScore returned 100 in this case, ignoring the active violations.
	a := &report.Assessment{
		Summary: evaluation.ComplianceSummary{
			TotalAssets: 0,
			Violations:  5,
		},
	}

	score := computeSimpleScore(a)
	if score != 0 {
		t.Fatalf("expected score to be 0 for zero assets with active violations, got %v (perfect score 100 was returned)", score)
	}
}

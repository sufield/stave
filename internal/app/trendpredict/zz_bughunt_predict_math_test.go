package trendpredict

import (
	"math"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Predict_NegativeReadinessAndCeilLimit(t *testing.T) {
	// A scenario where Violations (8) exceeds TotalAssets (5).
	// Under the buggy code:
	// currentReadiness = (1.0 - 8.0/5.0) * 100 = -60%
	// If target is 90%, gap = 90 - (-60) = 150%.
	// controlsToFix = ceil(8 * 1.5) = 12.
	// This is mathematically invalid (we cannot fix more findings than we have).
	assessments := []*report.Assessment{
		{
			Run: evaluation.RunInfo{Now: now.Add(-30 * 24 * time.Hour)},
			Summary: evaluation.ComplianceSummary{
				TotalAssets: 5,
				Violations:  8,
			},
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityCritical),
				finding("CTL.A.002", policy.SeverityCritical),
				finding("CTL.A.003", policy.SeverityCritical),
				finding("CTL.A.004", policy.SeverityCritical),
				finding("CTL.A.005", policy.SeverityCritical),
				finding("CTL.A.006", policy.SeverityCritical),
				finding("CTL.A.007", policy.SeverityCritical),
				finding("CTL.A.008", policy.SeverityCritical),
			},
		},
		{
			Run: evaluation.RunInfo{Now: now},
			Summary: evaluation.ComplianceSummary{
				TotalAssets: 5,
				Violations:  8,
			},
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityCritical),
				finding("CTL.A.002", policy.SeverityCritical),
				finding("CTL.A.003", policy.SeverityCritical),
				finding("CTL.A.004", policy.SeverityCritical),
				finding("CTL.A.005", policy.SeverityCritical),
				finding("CTL.A.006", policy.SeverityCritical),
				finding("CTL.A.007", policy.SeverityCritical),
				finding("CTL.A.008", policy.SeverityCritical),
			},
		},
	}

	p := Predict(Input{
		Assessments:     assessments,
		Profile:         "hipaa",
		TargetReadiness: 90,
		Window:          90 * 24 * time.Hour,
		Now:             now,
	})

	if p.CurrentReadiness < 0 {
		t.Errorf("CurrentReadiness should not be negative, got %.2f", p.CurrentReadiness)
	}

	// We calculate how many controls we need to fix.
	// Since we only have 8 findings, we should never need to fix more than 8 findings.
	gap := 90.0 - p.CurrentReadiness
	controlsToFix := int(math.Ceil(float64(len(assessments[1].Findings)) * gap / 100))
	if controlsToFix > len(assessments[1].Findings) {
		t.Errorf("controlsToFix (%d) should not exceed total findings (%d)", controlsToFix, len(assessments[1].Findings))
	}
}

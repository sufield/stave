package trendpredict

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestPredict_ZeroWindowUsesAllHistory(t *testing.T) {
	evalTime := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	openTime := evalTime.Add(-40 * 24 * time.Hour)
	closeTime := evalTime.Add(-10 * 24 * time.Hour) // Dwell time is 30 days

	assessments := []*report.Assessment{
		{
			Run:     evaluation.RunInfo{EvalTime: openTime},
			Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 1},
			Findings: []remediation.Finding{
				{
					ControlID:       kernel.ControlID("CTL.A"),
					AssetID:         "asset1",
					ControlSeverity: policy.SeverityCritical,
				},
			},
		},
		{
			// Finding was closed here
			Run:     evaluation.RunInfo{EvalTime: closeTime},
			Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 0},
		},
		{
			// Now a new finding was opened to simulate a gap
			Run:     evaluation.RunInfo{EvalTime: evalTime},
			Summary: evaluation.ComplianceSummary{TotalAssets: 10, Violations: 1},
			Findings: []remediation.Finding{
				{
					ControlID:       kernel.ControlID("CTL.B"),
					AssetID:         "asset1",
					ControlSeverity: policy.SeverityCritical,
				},
			},
		},
	}

	p := Predict(Input{
		Assessments:     assessments,
		Profile:         "test",
		TargetReadiness: 100,
		Window:          0, // 0 should use all history, meaning MTTR = 30 days
		EvalTime:        evalTime,
	})

	// If MTTR is correctly computed as 30 days (from the 30-day closed finding history),
	// projectedDays = controlsToFix (1) * avgMTTRDays (30) = 30 days.
	// If it was not computed (due to the bug filtering it out), it falls back to 14 days.
	diffDays := int(p.ProjectedDate.Sub(evalTime).Hours() / 24)
	if diffDays == 14 {
		t.Errorf("MTTR calculation failed when Window is 0: fell back to default 14 days, expected 30 days")
	} else if diffDays != 30 {
		t.Errorf("Expected projected days to be 30, got %d", diffDays)
	}
}

package trendpredict

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

var now = time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

func finding(ctl string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID("asset1"),
			ControlSeverity: sev,
		},
	}
}

func TestPredict_ProjectionDateComputed(t *testing.T) {
	assessments := []*report.Assessment{
		{
			Run:     evaluation.RunInfo{EvalTime: now.Add(-30 * 24 * time.Hour)},
			Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 20},
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityCritical),
			},
		},
		{
			Run:     evaluation.RunInfo{EvalTime: now},
			Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 15},
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityCritical),
			},
		},
	}

	p := Predict(Input{
		Assessments:     assessments,
		Profile:         "hipaa",
		TargetReadiness: 95,
		Window:          90 * 24 * time.Hour,
		EvalTime:        now,
	})

	if p.ProjectedDate.Before(now) {
		t.Errorf("projected date %s should be after now", p.ProjectedDate)
	}
	if p.CurrentReadiness == 0 {
		t.Error("current readiness should be computed")
	}
}

func TestPredict_AlreadyMeetsTarget(t *testing.T) {
	assessments := []*report.Assessment{
		{
			Run:     evaluation.RunInfo{EvalTime: now},
			Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 2},
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityLow),
			},
		},
	}

	p := Predict(Input{
		Assessments:     assessments,
		Profile:         "hipaa",
		TargetReadiness: 95,
		Window:          90 * 24 * time.Hour,
		EvalTime:        now,
	})

	if !p.ProjectedDate.Equal(now) {
		t.Errorf("should project today when already meeting target (readiness=%.1f)", p.CurrentReadiness)
	}
}

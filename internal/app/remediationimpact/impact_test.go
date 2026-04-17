package remediationimpact

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func finding(ctl string, ast string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID(ast),
			ControlSeverity: sev,
		},
	}
}

func TestAnalyze_ClosedFindingsDetected(t *testing.T) {
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 10},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "asset1", policy.SeverityHigh),
			finding("CTL.B.001", "asset2", policy.SeverityHigh),
		},
	}
	after := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 5},
		Findings: []remediation.Finding{
			finding("CTL.B.001", "asset2", policy.SeverityHigh),
		},
	}

	r := Analyze(Input{Before: before, After: after})

	if len(r.Closed) != 1 {
		t.Fatalf("closed = %d, want 1", len(r.Closed))
	}
	if r.Closed[0].ControlID != "CTL.A.001" {
		t.Errorf("closed control = %s, want CTL.A.001", r.Closed[0].ControlID)
	}
	if r.ScoreDelta <= 0 {
		t.Errorf("score delta = %.1f, want positive", r.ScoreDelta)
	}
}

func TestAnalyze_EfficiencyRatioComputed(t *testing.T) {
	before := &report.Assessment{
		Summary: evaluation.ComplianceSummary{TotalAssets: 100, Violations: 20},
		Findings: []remediation.Finding{
			finding("CTL.A.001", "a1", policy.SeverityHigh),
		},
	}
	after := &report.Assessment{
		Summary:  evaluation.ComplianceSummary{TotalAssets: 100, Violations: 10},
		Findings: []remediation.Finding{},
	}

	r := Analyze(Input{
		Before:         before,
		After:          after,
		PredictedDelta: 12.0,
	})

	if r.Efficiency == nil {
		t.Fatal("efficiency should be computed when PredictedDelta > 0")
	}
	if r.Efficiency.Ratio <= 0 {
		t.Errorf("ratio = %.2f, want > 0", r.Efficiency.Ratio)
	}
	if r.Efficiency.Verdict == "" {
		t.Error("verdict should be set")
	}
}

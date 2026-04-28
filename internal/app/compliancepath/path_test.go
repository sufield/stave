package compliancepath

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func finding(ctl, action string, frameworks map[policy.ComplianceFramework]string) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:         kernel.ControlID(ctl),
			AssetID:           asset.ID("asset1"),
			ControlSeverity:   policy.SeverityHigh,
			ControlCompliance: policy.ComplianceMapping(frameworks),
		},
		RemediationSpec: policy.RemediationSpec{Action: action},
	}
}

func TestCompute_GreedyPicksHighestCoverage(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", "enable-cloudtrail", map[policy.ComplianceFramework]string{"soc2": "CC7.2", "hipaa": "164.312"}),
		finding("CTL.A.002", "enable-cloudtrail", map[policy.ComplianceFramework]string{"soc2": "CC7.3"}),
		finding("CTL.B.001", "enable-mfa", map[policy.ComplianceFramework]string{"soc2": "CC6.1"}),
	}

	result, err := Compute(Input{
		Findings:        findings,
		TargetFramework: "soc2",
		TargetReadiness: 90,
		TotalControls:   10,
	})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if len(result.Bundles) == 0 {
		t.Fatal("expected at least one bundle")
	}
	// Greedy should pick "enable-cloudtrail" first (covers 2 controls).
	if result.Bundles[0].Action != "enable-cloudtrail" {
		t.Errorf("first bundle = %s, want enable-cloudtrail (highest coverage)", result.Bundles[0].Action)
	}
	if len(result.Bundles[0].ControlIDs) != 2 {
		t.Errorf("first bundle controls = %d, want 2", len(result.Bundles[0].ControlIDs))
	}
}

func TestCompute_EffortModelApplied(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", "fix-a", nil),
	}

	result, err := Compute(Input{
		Findings:        findings,
		TargetFramework: "soc2",
		TargetReadiness: 95,
		TotalControls:   10,
		Effort: &EffortModel{
			DefaultHours: 4,
			Controls:     map[string]float64{"CTL.A.001": 2},
		},
	})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	if result.TotalEffort != 2 {
		t.Errorf("effort = %.0f, want 2 (from effort model)", result.TotalEffort)
	}
}

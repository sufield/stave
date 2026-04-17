package sprintplanner

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func finding(ctlID string, assetID string, sev policy.Severity, dwellHours float64) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctlID),
			AssetID:         asset.ID(assetID),
			ControlSeverity: sev,
			Evidence: evaluation.Evidence{
				UnsafeDurationHours: dwellHours,
			},
		},
	}
}

func TestPlan_StaysWithinBudget(t *testing.T) {
	input := Input{
		Findings: []remediation.Finding{
			finding("ctl-1", "asset-a", policy.SeverityCritical, 100),
			finding("ctl-2", "asset-b", policy.SeverityHigh, 50),
			finding("ctl-3", "asset-c", policy.SeverityMedium, 25),
		},
		CapacityHours: 10,
		DefaultHours:  4,
		ControlHours:  map[string]float64{"ctl-1": 6, "ctl-2": 3},
	}

	result := Plan(input)

	if result.TotalHours > result.Capacity {
		t.Errorf("total hours %v exceeds capacity %v", result.TotalHours, result.Capacity)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected at least one item in sprint")
	}
	if len(result.LeftOut) == 0 {
		t.Fatal("expected at least one item left out")
	}
	// ctl-2 has ROI=50/3≈16.7, ctl-1 has ROI=100/6≈16.7, ctl-3 has ROI=25/4=6.25
	// With 10h budget: ctl-2 (3h) + ctl-1 (6h) = 9h, ctl-3 left out
	if result.TotalHours > 10 {
		t.Errorf("budget exceeded: got %v hours", result.TotalHours)
	}
}

func TestPlan_OpportunityCostCorrect(t *testing.T) {
	input := Input{
		Findings: []remediation.Finding{
			finding("expensive", "asset-a", policy.SeverityCritical, 200),
			finding("cheap-1", "asset-b", policy.SeverityHigh, 10),
			finding("cheap-2", "asset-c", policy.SeverityHigh, 10),
		},
		CapacityHours: 8,
		DefaultHours:  4,
		ControlHours:  map[string]float64{"expensive": 20},
	}

	result := Plan(input)

	// expensive has ROI=200/20=10, cheap items have ROI=10/4=2.5
	// Budget is 8h. expensive costs 20h and does not fit.
	// cheap-1 (4h) + cheap-2 (4h) = 8h.
	if len(result.LeftOut) != 1 {
		t.Fatalf("expected 1 left out, got %d", len(result.LeftOut))
	}
	if result.LeftOut[0].ControlID != "expensive" {
		t.Errorf("expected 'expensive' left out, got %q", result.LeftOut[0].ControlID)
	}
	if result.TotalHours != 8 {
		t.Errorf("expected 8 total hours, got %v", result.TotalHours)
	}
	if result.RiskReduction != 20 {
		t.Errorf("expected risk reduction 20, got %v", result.RiskReduction)
	}
}

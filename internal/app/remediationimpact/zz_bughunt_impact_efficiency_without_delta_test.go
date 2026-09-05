package remediationimpact

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Analyze_EfficiencyWithoutDelta(t *testing.T) {
	// Before assessment has one finding on CTL.1
	before := &report.Assessment{
		Findings: []remediation.Finding{
			{ControlID: kernel.ControlID("CTL.1")},
		},
	}
	// After assessment also has the same finding on CTL.1
	after := &report.Assessment{
		Findings: []remediation.Finding{
			{ControlID: kernel.ControlID("CTL.1")},
		},
	}

	// We predict CTL.1 will be closed, but do not provide PredictedDelta
	input := Input{
		Before:          before,
		After:           after,
		PredictedDelta:  0.0,
		PredictedClosed: []string{"CTL.1"},
	}

	report, err := Analyze(input)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.Efficiency == nil {
		t.Fatalf("expected report.Efficiency to be populated when PredictedClosed is provided, but it was nil")
	}
	if len(report.Efficiency.StillOpen) != 1 || report.Efficiency.StillOpen[0] != "CTL.1" {
		t.Errorf("expected CTL.1 to be in StillOpen list, got: %v", report.Efficiency.StillOpen)
	}
}

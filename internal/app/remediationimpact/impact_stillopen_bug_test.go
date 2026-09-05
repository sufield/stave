package remediationimpact

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestAnalyze_StillOpenDeterministicAndDeduplicated(t *testing.T) {
	before := &report.Assessment{
		Findings: []remediation.Finding{
			{ControlID: "CTL.B", AssetID: asset.ID("ast-1")},
			{ControlID: "CTL.A", AssetID: asset.ID("ast-2")},
		},
		Summary: evaluation.ComplianceSummary{TotalAssets: 2, Violations: 2},
	}

	after := &report.Assessment{
		Findings: []remediation.Finding{
			{ControlID: "CTL.B", AssetID: asset.ID("ast-1")},
			{ControlID: "CTL.A", AssetID: asset.ID("ast-2")},
			{ControlID: "CTL.A", AssetID: asset.ID("ast-3")}, // duplicate CTL.A in after
		},
		Summary: evaluation.ComplianceSummary{TotalAssets: 3, Violations: 3},
	}

	input := Input{
		Before:          before,
		After:           after,
		PredictedDelta:  10,
		PredictedClosed: []string{"CTL.B", "CTL.A", "CTL.B"}, // includes duplicates & unsorted
	}

	rep, err := Analyze(input)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if rep.Efficiency == nil {
		t.Fatalf("expected Efficiency report")
	}

	wantStillOpen := []string{"CTL.A", "CTL.B"}
	if !reflect.DeepEqual(rep.Efficiency.StillOpen, wantStillOpen) {
		t.Errorf("expected StillOpen sorted & deduplicated %v, got %v", wantStillOpen, rep.Efficiency.StillOpen)
	}
}

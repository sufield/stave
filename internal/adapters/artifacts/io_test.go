package artifacts

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

func TestCompareBaseline_FindsNewAndResolved(t *testing.T) {
	base := []evaluation.BaselineEntry{
		{ControlID: "CTL.TEST.A.001", AssetID: "res-1"},
		{ControlID: "CTL.TEST.B.001", AssetID: "res-2"},
	}
	current := []evaluation.BaselineEntry{
		{ControlID: "CTL.TEST.B.001", AssetID: "res-2"},
		{ControlID: "CTL.TEST.C.001", AssetID: "res-3"},
	}

	comparison := evaluation.CompareBaseline(base, current)
	if len(comparison.New) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(comparison.New))
	}
	if comparison.New[0].ControlID != "CTL.TEST.C.001" || comparison.New[0].AssetID != "res-3" {
		t.Fatalf("unexpected new finding: %+v", comparison.New[0])
	}
	if len(comparison.Resolved) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(comparison.Resolved))
	}
	if comparison.Resolved[0].ControlID != "CTL.TEST.A.001" || comparison.Resolved[0].AssetID != "res-1" {
		t.Fatalf("unexpected resolved finding: %+v", comparison.Resolved[0])
	}
}

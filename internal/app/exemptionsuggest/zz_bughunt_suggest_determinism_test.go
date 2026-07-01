package exemptionsuggest

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Suggest_Determinism(t *testing.T) {
	// Multiple chronic candidates with identical severity and dwell days.
	// Since Suggest iterates a map to collect them and doesn't break ties deterministically,
	// the output order is non-deterministic in the original code.
	history := []*report.Assessment{
		assessment(t0,
			finding("CTL.Z.001", "asset1", policy.SeverityHigh),
			finding("CTL.A.001", "asset1", policy.SeverityHigh),
		),
	}

	result := Suggest(Input{
		History:  history,
		Window:   90 * day,
		MinDwell: 0, // 0 dwell so they are chronic immediately
		Now:      tNow,
	})

	if len(result.Chronic) != 2 {
		t.Fatalf("expected 2 chronic candidates, got %d", len(result.Chronic))
	}

	// We expect they are sorted alphabetically by ControlID as the tie-breaker: CTL.A.001 then CTL.Z.001
	if result.Chronic[0].ControlID != "CTL.A.001" {
		t.Errorf("result.Chronic[0] = %s, want CTL.A.001", result.Chronic[0].ControlID)
	}
	if result.Chronic[1].ControlID != "CTL.Z.001" {
		t.Errorf("result.Chronic[1] = %s, want CTL.Z.001", result.Chronic[1].ControlID)
	}
}

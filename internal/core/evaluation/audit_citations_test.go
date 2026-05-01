package evaluation

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestCalculateReadiness_CitationsCountSatisfiedOnly verifies that
// FrameworkCitationsSatisfied counts only citations whose backing
// control passes — not every tagged control regardless of pass/fail.
func TestCalculateReadiness_CitationsCountSatisfiedOnly(t *testing.T) {
	r := &ComplianceReport{
		Findings: []Finding{
			{ControlID: "CTL.A"},
		},
	}
	allControlIDs := []kernel.ControlID{"CTL.A", "CTL.B"}
	controlCompliance := map[kernel.ControlID]map[policy.ComplianceFramework]string{
		"CTL.A": {"soc2": "CC6.1"},
		"CTL.B": {"soc2": "CC6.2"},
	}
	r.CalculateReadiness([]string{"soc2"}, allControlIDs, controlCompliance)

	if got, want := r.Summary.FrameworkCitationsSatisfied, 1; got != want {
		t.Errorf("FrameworkCitationsSatisfied = %d, want %d (only CTL.B passes; CTL.A failing should not count)", got, want)
	}
	if len(r.Summary.FrameworkReadiness) != 1 {
		t.Fatalf("expected 1 readiness entry, got %d", len(r.Summary.FrameworkReadiness))
	}
	fr := r.Summary.FrameworkReadiness[0]
	if fr.TotalControls != 2 || fr.PassingControls != 1 {
		t.Errorf("readiness counts: total=%d passing=%d, want 2/1", fr.TotalControls, fr.PassingControls)
	}
}

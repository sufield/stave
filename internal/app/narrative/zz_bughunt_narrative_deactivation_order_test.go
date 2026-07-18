package narrative

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_ChainDeactivationOrder_DeterministicSameStage(t *testing.T) {
	// CTL.LOG.002 and CTL.AUDIT.001 both map to stageOrder 0 (detection first).
	// Under buggy code, their relative order is unstable and depends on the input slice order
	// because stageOrder(a) - stageOrder(b) == 0 and there is no alphabetical tiebreaker.
	// We assert that they are sorted alphabetically: CTL.AUDIT.001 first, then CTL.LOG.002.
	controls := []kernel.ControlID{
		"CTL.LOG.002",
		"CTL.AUDIT.001",
	}

	order := chainDeactivationOrder(controls)

	if len(order) != 2 {
		t.Fatalf("expected 2 controls in order, got %d", len(order))
	}

	if order[0] != "CTL.AUDIT.001" {
		t.Errorf("expected CTL.AUDIT.001 first, got %s", order[0])
	}
	if order[1] != "CTL.LOG.002" {
		t.Errorf("expected CTL.LOG.002 second, got %s", order[1])
	}
}

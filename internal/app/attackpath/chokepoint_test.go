package attackpath

import (
	"testing"

	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestFindChokePoints_SharedControl(t *testing.T) {
	cfs := []findings.CompoundFinding{
		{
			ChainID:         "chain_a",
			ControlsFailing: []kernel.ControlID{"CTL.1", "CTL.2", "CTL.SHARED"},
		},
		{
			ChainID:         "chain_b",
			ControlsFailing: []kernel.ControlID{"CTL.3", "CTL.SHARED"},
		},
		{
			ChainID:         "chain_c",
			ControlsFailing: []kernel.ControlID{"CTL.4", "CTL.SHARED"},
		},
	}

	result := FindChokePoints(cfs)
	if len(result) != 1 {
		t.Fatalf("got %d choke points, want 1", len(result))
	}
	if result[0].ControlID != "CTL.SHARED" {
		t.Errorf("got control %s, want CTL.SHARED", result[0].ControlID)
	}
	if result[0].SharedChainCount != 3 {
		t.Errorf("got count %d, want 3", result[0].SharedChainCount)
	}
}

func TestFindChokePoints_MultipleChokePoints(t *testing.T) {
	cfs := []findings.CompoundFinding{
		{
			ChainID:         "chain_a",
			ControlsFailing: []kernel.ControlID{"CTL.X", "CTL.Y"},
		},
		{
			ChainID:         "chain_b",
			ControlsFailing: []kernel.ControlID{"CTL.X", "CTL.Y", "CTL.Z"},
		},
		{
			ChainID:         "chain_c",
			ControlsFailing: []kernel.ControlID{"CTL.X"},
		},
	}

	result := FindChokePoints(cfs)
	if len(result) != 2 {
		t.Fatalf("got %d choke points, want 2", len(result))
	}
	// CTL.X appears in 3, CTL.Y in 2
	if result[0].ControlID != "CTL.X" || result[0].SharedChainCount != 3 {
		t.Errorf("first choke: got %s(%d), want CTL.X(3)", result[0].ControlID, result[0].SharedChainCount)
	}
	if result[1].ControlID != "CTL.Y" || result[1].SharedChainCount != 2 {
		t.Errorf("second choke: got %s(%d), want CTL.Y(2)", result[1].ControlID, result[1].SharedChainCount)
	}
}

func TestFindChokePoints_NoSharedControls(t *testing.T) {
	cfs := []findings.CompoundFinding{
		{ChainID: "chain_a", ControlsFailing: []kernel.ControlID{"CTL.1"}},
		{ChainID: "chain_b", ControlsFailing: []kernel.ControlID{"CTL.2"}},
	}
	result := FindChokePoints(cfs)
	if len(result) != 0 {
		t.Errorf("got %d choke points, want 0", len(result))
	}
}

func TestFindChokePoints_Empty(t *testing.T) {
	result := FindChokePoints(nil)
	if result != nil {
		t.Errorf("got %v, want nil", result)
	}
}

func TestFindChokePoints_ChainIDsDeterministic(t *testing.T) {
	cfs := []findings.CompoundFinding{
		{ChainID: "z_chain", ControlsFailing: []kernel.ControlID{"CTL.1"}},
		{ChainID: "a_chain", ControlsFailing: []kernel.ControlID{"CTL.1"}},
		{ChainID: "m_chain", ControlsFailing: []kernel.ControlID{"CTL.1"}},
	}

	result := FindChokePoints(cfs)
	if len(result) != 1 {
		t.Fatalf("got %d, want 1", len(result))
	}
	want := []kernel.ChainID{"a_chain", "m_chain", "z_chain"}
	for i, id := range result[0].ChainIDs {
		if id != want[i] {
			t.Errorf("chain[%d] = %s, want %s", i, id, want[i])
		}
	}
}

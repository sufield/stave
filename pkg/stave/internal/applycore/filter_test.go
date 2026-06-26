package applycore

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestFilterControlsByID(t *testing.T) {
	all := []policy.ControlDefinition{
		{ID: kernel.ControlID("CTL.A")},
		{ID: kernel.ControlID("CTL.B")},
		{ID: kernel.ControlID("CTL.C")},
	}

	got := filterControlsByID(all, []string{"CTL.C", "CTL.A", "CTL.MISSING"})

	// Keeps only allowed IDs, in catalog order (not allowlist order), and
	// silently drops IDs not present in the catalog.
	want := []string{"CTL.A", "CTL.C"}
	if len(got) != len(want) {
		t.Fatalf("got %d controls, want %d: %v", len(got), len(want), got)
	}
	for i, id := range want {
		if string(got[i].ID) != id {
			t.Errorf("position %d: got %q, want %q", i, got[i].ID, id)
		}
	}
}

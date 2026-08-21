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

func TestFilterByLifecycle(t *testing.T) {
	all := []policy.ControlDefinition{
		{ID: "CTL.ACTIVE", Lifecycle: policy.ControlLifecycle{}},
		{ID: "CTL.SUNSET", Lifecycle: policy.ControlLifecycle{Status: policy.LifecycleSunset}},
		{ID: "CTL.EOL", Lifecycle: policy.ControlLifecycle{Status: policy.LifecycleEOL}},
		{ID: "CTL.MAINT", Lifecycle: policy.ControlLifecycle{Status: policy.LifecycleMaintenance}},
	}

	got := filterByLifecycle(all, []string{"eol", "sunset"})
	if len(got) != 2 {
		t.Fatalf("got %d controls, want 2", len(got))
	}
	if got[0].ID != "CTL.ACTIVE" {
		t.Errorf("got[0] = %q, want CTL.ACTIVE", got[0].ID)
	}
	if got[1].ID != "CTL.MAINT" {
		t.Errorf("got[1] = %q, want CTL.MAINT", got[1].ID)
	}
}

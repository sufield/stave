package compliance

import "testing"

func TestNewTestCatalog_ProducesSameControlsAsGlobal(t *testing.T) {
	isolated := NewTestCatalog()
	if isolated.Len() != GetControlRegistry().Len() {
		t.Fatalf("NewTestCatalog has %d controls, global has %d", isolated.Len(), GetControlRegistry().Len())
	}

	// Verify every control from the global is present in the isolated catalog.
	for _, ctl := range GetControlRegistry().All() {
		id := ctl.Def().ID()
		found := isolated.Lookup(id)
		if found == nil {
			t.Errorf("NewTestCatalog missing control %s", id)
		}
	}
}

func TestNewTestCatalog_IsIsolated(t *testing.T) {
	a := NewTestCatalog()
	b := NewTestCatalog()

	// Two catalogs should be independent instances.
	if &a == &b {
		t.Fatal("NewTestCatalog should return fresh instances")
	}
}

func TestNewCatalogWith_Subset(t *testing.T) {
	full := NewTestCatalog()
	if full.Len() < 2 {
		t.Skip("need at least 2 controls")
	}

	first := full.All()[0]
	subset := NewCatalogWith(first)
	if subset.Len() != 1 {
		t.Fatalf("subset has %d controls, want 1", subset.Len())
	}
	if subset.Lookup(first.Def().ID()) == nil {
		t.Fatal("subset missing the control we added")
	}
}

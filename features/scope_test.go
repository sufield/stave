package features

import "testing"

func TestOutOfScope_ParsesAndIsWellFormed(t *testing.T) {
	entries, err := OutOfScope()
	if err != nil {
		t.Fatalf("OutOfScope: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one out-of-scope entry")
	}

	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.ID == "" {
			t.Errorf("entry %q has empty id", e.Label)
		}
		if e.Label == "" {
			t.Errorf("entry %q has empty label", e.ID)
		}
		if e.Reason == "" {
			t.Errorf("entry %q has empty reason", e.ID)
		}
		if _, ok := seen[e.ID]; ok {
			t.Errorf("duplicate out-of-scope id %q", e.ID)
		}
		seen[e.ID] = struct{}{}
	}
}

func TestOutOfScopeIDs_MatchEntries(t *testing.T) {
	entries, err := OutOfScope()
	if err != nil {
		t.Fatalf("OutOfScope: %v", err)
	}
	ids, err := OutOfScopeIDs()
	if err != nil {
		t.Fatalf("OutOfScopeIDs: %v", err)
	}
	if len(ids) != len(entries) {
		t.Fatalf("ids len %d != entries len %d", len(ids), len(entries))
	}
}

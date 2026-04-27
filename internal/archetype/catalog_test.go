package archetype

import "testing"

func TestCatalog_HasTwelveArchetypes(t *testing.T) {
	if got := len(Catalog); got != 12 {
		t.Fatalf("Catalog length = %d, want 12", got)
	}
}

func TestCatalog_NoDuplicateIDs(t *testing.T) {
	seen := make(map[string]int, len(Catalog))
	for i, a := range Catalog {
		if prev, ok := seen[a.ID]; ok {
			t.Errorf("duplicate ID %q at indices %d and %d", a.ID, prev, i)
		}
		seen[a.ID] = i
	}
}

func TestCatalog_RequiredFields(t *testing.T) {
	for _, a := range Catalog {
		if a.ID == "" {
			t.Errorf("archetype with empty ID: %+v", a)
		}
		if a.Name == "" {
			t.Errorf("archetype %q has empty Name", a.ID)
		}
		if a.Description == "" {
			t.Errorf("archetype %q has empty Description", a.ID)
		}
		if a.Guidance == "" {
			t.Errorf("archetype %q has empty Guidance", a.ID)
		}
		if len(a.Services) == 0 {
			t.Errorf("archetype %q has no services", a.ID)
		}
	}
}

func TestLookup_Roundtrip(t *testing.T) {
	for _, a := range Catalog {
		got, ok := Lookup(a.ID)
		if !ok {
			t.Errorf("Lookup(%q) returned ok=false; want true", a.ID)
			continue
		}
		if got.ID != a.ID {
			t.Errorf("Lookup(%q).ID = %q; want %q", a.ID, got.ID, a.ID)
		}
	}
}

func TestLookup_UnknownID(t *testing.T) {
	if _, ok := Lookup("not-a-real-archetype"); ok {
		t.Error("Lookup of unknown ID returned ok=true; want false")
	}
}

func TestIDs_MatchesCatalog(t *testing.T) {
	ids := IDs()
	if len(ids) != len(Catalog) {
		t.Fatalf("IDs() length = %d, want %d", len(ids), len(Catalog))
	}
	for i, id := range ids {
		if id != Catalog[i].ID {
			t.Errorf("IDs[%d] = %q, want %q", i, id, Catalog[i].ID)
		}
	}
}

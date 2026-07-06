package taxonomy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestVocabulary_AllCategoriesHaveMetadata(t *testing.T) {
	vocab := Vocabulary()
	if len(vocab) != len(All) {
		t.Fatalf("Vocabulary has %d entries, All has %d", len(vocab), len(All))
	}
	seen := make(map[kernel.CategoryID]bool)
	for _, c := range vocab {
		if c.Name == "" {
			t.Errorf("category %s has empty Name", c.ID)
		}
		if c.Definition == "" {
			t.Errorf("category %s has empty Definition", c.ID)
		}
		if len(c.Examples) == 0 {
			t.Errorf("category %s has no Examples", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("duplicate category %s", c.ID)
		}
		seen[c.ID] = true
	}
	for _, id := range All {
		if !seen[id] {
			t.Errorf("category %s in All but missing from Vocabulary", id)
		}
	}
}

func TestLookupCategory_Known(t *testing.T) {
	cat, ok := LookupCategory(LeastPrivilege)
	if !ok {
		t.Fatal("expected to find least-privilege")
	}
	if cat.Name != "Least Privilege" {
		t.Errorf("expected name Least Privilege, got %q", cat.Name)
	}
}

func TestLookupCategory_Unknown(t *testing.T) {
	_, ok := LookupCategory("nonexistent-category")
	if ok {
		t.Fatal("expected unknown category to return false")
	}
}

func TestCategoryName_Known(t *testing.T) {
	name := CategoryName(FormalSemantics)
	if name != "Policy Evaluation Semantics" {
		t.Errorf("expected Policy Evaluation Semantics, got %q", name)
	}
}

func TestCategoryName_Unknown(t *testing.T) {
	name := CategoryName("mystery")
	if name != "mystery" {
		t.Errorf("expected raw ID fallback, got %q", name)
	}
}

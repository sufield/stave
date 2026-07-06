package builtin

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/core/kernel"
)

func testRegistry() *ControlStore {
	return NewControlStore(EmbeddedFS(), "embedded", WithAliasResolver(predicate.ResolverFunc()))
}

func TestLoadAll(t *testing.T) {
	t.Parallel()
	controls, err := testRegistry().All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	if len(controls) == 0 {
		t.Fatal("expected at least one embedded control")
	}

	// Verify sorted by ID
	for i := 1; i < len(controls); i++ {
		if controls[i].ID < controls[i-1].ID {
			t.Errorf("controls not sorted: %s < %s at index %d", controls[i].ID, controls[i-1].ID, i)
		}
	}

	// Verify known control exists with domain and scope_tags parsed
	found := false
	for _, ctl := range controls {
		if ctl.ID == "CTL.S3.PUBLIC.001" {
			found = true
			if ctl.Domain != "exposure" {
				t.Errorf("CTL.S3.PUBLIC.001 domain: got %q, want %q", ctl.Domain, "exposure")
			}
			if len(ctl.ScopeTags) < 2 {
				t.Errorf("CTL.S3.PUBLIC.001 scope_tags: got %v, want at least [aws, s3]", ctl.ScopeTags)
			}
			break
		}
	}
	if !found {
		t.Error("CTL.S3.PUBLIC.001 not found in embedded controls")
	}
}

func TestLoadFiltered_ByScopeTags(t *testing.T) {
	t.Parallel()
	selectors := []Selector{
		{Tags: []string{"aws", "s3"}},
	}
	controls, err := testRegistry().Filtered(selectors)
	if err != nil {
		t.Fatalf("Filtered failed: %v", err)
	}
	if len(controls) == 0 {
		t.Fatal("expected at least one control matching aws/s3 tags")
	}

	// Verify all returned controls have the required tags
	for _, ctl := range controls {
		tags := make(map[kernel.ScopeTag]struct{}, len(ctl.ScopeTags))
		for _, tag := range ctl.ScopeTags {
			tags[tag] = struct{}{}
		}
		if _, ok1 := tags["aws"]; !ok1 {
			t.Errorf("control %s scope_tags %v does not contain [aws, s3]", ctl.ID, ctl.ScopeTags)
		} else if _, ok2 := tags["s3"]; !ok2 {
			t.Errorf("control %s scope_tags %v does not contain [aws, s3]", ctl.ID, ctl.ScopeTags)
		}
	}
}

func TestLoadFiltered_EmptySelectors(t *testing.T) {
	t.Parallel()
	reg := testRegistry()
	all, err := reg.All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	filtered, err := reg.Filtered(nil)
	if err != nil {
		t.Fatalf("Filtered(nil) failed: %v", err)
	}
	if len(all) != len(filtered) {
		t.Errorf("empty selectors: got %d controls, want %d", len(filtered), len(all))
	}
}

func TestLoadAll_NoDuplicateIDs(t *testing.T) {
	t.Parallel()
	controls, err := testRegistry().All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	seen := make(map[kernel.ControlID]struct{}, len(controls))
	for _, ctl := range controls {
		if _, ok := seen[ctl.ID]; ok {
			t.Errorf("duplicate control ID: %s", ctl.ID)
		}
		seen[ctl.ID] = struct{}{}
	}
}

func TestLoadAll_AllControlsHaveTaxonomy(t *testing.T) {
	t.Parallel()
	controls, err := testRegistry().All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	var missing []kernel.ControlID
	for _, ctl := range controls {
		if len(ctl.Taxonomy) == 0 {
			missing = append(missing, ctl.ID)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d/%d controls have no taxonomy (first 5: %v)",
			len(missing), len(controls), missing[:min(5, len(missing))])
	}
}

func TestLoadAll_AliasesAreExpanded(t *testing.T) {
	t.Parallel()
	controls, err := testRegistry().All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	for _, ctl := range controls {
		if ctl.UnsafePredicateAlias == "" {
			continue
		}
		if len(ctl.UnsafePredicate.Any) == 0 && len(ctl.UnsafePredicate.All) == 0 {
			t.Errorf("control %s has unsafe_predicate_alias %q but UnsafePredicate was not expanded",
				ctl.ID, ctl.UnsafePredicateAlias)
		}
	}
}

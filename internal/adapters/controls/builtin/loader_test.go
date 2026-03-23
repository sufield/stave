package builtin

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func testRegistry() *Registry {
	return NewRegistry(EmbeddedFS(), "embedded")
}

func TestLoadAll(t *testing.T) {
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
		tags := make(map[string]bool, len(ctl.ScopeTags))
		for _, tag := range ctl.ScopeTags {
			tags[tag] = true
		}
		if !tags["aws"] || !tags["s3"] {
			t.Errorf("control %s scope_tags %v does not contain [aws, s3]", ctl.ID, ctl.ScopeTags)
		}
	}
}

func TestLoadFiltered_EmptySelectors(t *testing.T) {
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
	controls, err := testRegistry().All()
	if err != nil {
		t.Fatalf("All failed: %v", err)
	}
	seen := make(map[kernel.ControlID]bool, len(controls))
	for _, ctl := range controls {
		if seen[ctl.ID] {
			t.Errorf("duplicate control ID: %s", ctl.ID)
		}
		seen[ctl.ID] = true
	}
}

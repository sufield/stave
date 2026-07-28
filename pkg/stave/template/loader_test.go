package template

import (
	"testing"

	"github.com/sufield/stave/internal/templates"
)

func TestLoadFromFS_BuiltinTemplates(t *testing.T) {
	loaded, err := LoadFromFS(templates.BuiltinTemplateFS, ".")
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded) != 5 {
		t.Fatalf("expected 5 templates, got %d", len(loaded))
	}

	names := make(map[string]bool)
	for _, tmpl := range loaded {
		names[tmpl.Metadata.Name] = true
		if tmpl.APIVersion != "stave/v1" {
			t.Errorf("template %s: unexpected apiVersion %q", tmpl.Metadata.Name, tmpl.APIVersion)
		}
		if tmpl.RecommendWhen.Predicate == "" {
			t.Errorf("template %s: empty recommend_when predicate", tmpl.Metadata.Name)
		}
		if tmpl.RecommendWhen.Priority == 0 {
			t.Errorf("template %s: zero priority", tmpl.Metadata.Name)
		}
	}

	expected := []string{
		"bucket-hijacking-assessment",
		"m-and-a-diligence",
		"breach-reconstruction",
		"independent-audit",
		"critical-findings",
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing expected template: %s", name)
		}
	}
}

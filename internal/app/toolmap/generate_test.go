package toolmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestGenerateSkeleton_ValidYAML(t *testing.T) {
	gap := Gap{
		Tool:       "pacu",
		Capability: "iam_credential_theft",
		FieldPath:  "properties.identity.policies.has_admin_access",
	}

	data, err := GenerateSkeleton(gap)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Must parse as valid chain YAML.
	var chain policy.ChainDefinition
	if err := yaml.Unmarshal(data, &chain); err != nil {
		t.Fatalf("generated YAML doesn't parse: %v\n%s", err, data)
	}

	if chain.ID == "" {
		t.Error("chain ID should not be empty")
	}
	if len(chain.Postconditions) == 0 || chain.Postconditions[0] != "iam_credential_theft" {
		t.Errorf("expected postcondition iam_credential_theft, got %v", chain.Postconditions)
	}
}

func TestGenerateSkeleton_HasTODO(t *testing.T) {
	gap := Gap{
		Tool:       "cloudfox",
		Capability: "secret_store_access",
		FieldPath:  "properties.secret.access.rotation_enabled",
	}

	data, err := GenerateSkeleton(gap)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "TODO") {
		t.Error("skeleton should contain TODO markers")
	}
}

func TestGenerateSkeleton_CapabilityAnnotation(t *testing.T) {
	gap := Gap{
		Tool:       "stratus-red-team",
		Capability: "audit_trail_destroyed",
		FieldPath:  "properties.audit.kind",
	}

	data, err := GenerateSkeleton(gap)
	if err != nil {
		t.Fatal(err)
	}

	var chain policy.ChainDefinition
	if err := yaml.Unmarshal(data, &chain); err != nil {
		t.Fatal(err)
	}

	if len(chain.Postconditions) == 0 || chain.Postconditions[0] != "audit_trail_destroyed" {
		t.Errorf("expected capability annotation audit_trail_destroyed, got %v", chain.Postconditions)
	}
}

func TestGenerateAll_WritesFiles(t *testing.T) {
	dir := t.TempDir()
	gaps := []Gap{
		{Tool: "pacu", Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.has_admin_access"},
		{Tool: "cloudfox", Capability: "secret_store_access", FieldPath: "properties.secret.access.rotation_enabled"},
	}

	n, err := GenerateAll(gaps, dir)
	if err != nil {
		t.Fatalf("generate all: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 files written, got %d", n)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 files in dir, got %d", len(entries))
	}

	// Verify each generated file is valid YAML.
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var chain policy.ChainDefinition
		if err := yaml.Unmarshal(data, &chain); err != nil {
			t.Errorf("%s: invalid YAML: %v", e.Name(), err)
		}
	}
}

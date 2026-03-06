package schema

import (
	"encoding/json"
	"testing"
)

func TestLoadSchema(t *testing.T) {
	cases := []struct {
		kind    string
		version string
	}{
		{kind: KindControl, version: "v1"},
		{kind: KindObservation, version: "v1"},
		{kind: KindFinding, version: "v1"},
	}

	for _, tc := range cases {
		raw, err := LoadSchema(tc.kind, tc.version)
		if err != nil {
			t.Fatalf("LoadSchema(%s, %s) failed: %v", tc.kind, tc.version, err)
		}
		if len(raw) == 0 {
			t.Fatalf("LoadSchema(%s, %s) returned empty schema", tc.kind, tc.version)
		}
	}
}

func TestAllRegistryEntriesLoadable(t *testing.T) {
	for _, desc := range schemaRegistry {
		raw, err := LoadSchema(string(desc.kind), desc.version)
		if err != nil {
			t.Errorf("LoadSchema(%s, %s): %v", desc.kind, desc.version, err)
			continue
		}
		if len(raw) == 0 {
			t.Errorf("LoadSchema(%s, %s): returned empty bytes", desc.kind, desc.version)
			continue
		}
		if !json.Valid(raw) {
			t.Errorf("LoadSchema(%s, %s): embedded file is not valid JSON", desc.kind, desc.version)
		}
	}
}

func TestLoadSchema_DefaultVersion(t *testing.T) {
	raw, err := LoadSchema(KindControl, "")
	if err != nil {
		t.Fatalf("LoadSchema default version failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("expected non-empty schema bytes")
	}
}

package schema

import (
	"encoding/json"
	"testing"
)

func TestLoadSchema(t *testing.T) {
	cases := []struct {
		kind    Kind
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
	for kind, versions := range registry {
		for version := range versions {
			raw, err := LoadSchema(kind, version)
			if err != nil {
				t.Errorf("LoadSchema(%s, %s): %v", kind, version, err)
				continue
			}
			if len(raw) == 0 {
				t.Errorf("LoadSchema(%s, %s): returned empty bytes", kind, version)
				continue
			}
			if !json.Valid(raw) {
				t.Errorf("LoadSchema(%s, %s): embedded file is not valid JSON", kind, version)
			}
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

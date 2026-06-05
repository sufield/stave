package observations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test_RedGate_BundleEmptyType is a RED-gate test asserting the
// CORRECT, documented invariant that the bundle intake path and the
// directory single-file intake path produce snapshots of the SAME
// shape (CLAUDE.md: "bundle and directory loaders must match").
//
// An asset with an empty `type` ("") is a hard load error in
// single-file directory mode: the strict obs.v0.1 JSON-Schema
// validator enforces assets[].type minLength:1 / pattern
// ^[a-z0-9][a-z0-9_.-]*$, so the per-timestamp file is rejected with
// a schema-validation error (exit 2). The byte-identical asset routed
// through ParseBundle must be rejected too — otherwise it loads
// silently with Type=="" (kernel.AssetType.UnmarshalJSON coerces
// empty/unknown to "" without error), matches no control's scope, and
// produces a wrong COMPLIANT-looking verdict.
//
// This test asserts ParseBundle MUST return an error for the
// empty-type asset (correct behavior). Against current code ParseBundle
// returns no error and yields Type=="", so this test FAILS (goes red),
// proving the bug. It also confirms the asymmetry: the strict
// directory path rejects the same document.
func Test_RedGate_BundleEmptyType(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during RED gate test: %v", r)
		}
	}()

	// Bundle-shaped document: a single snapshot whose only asset has
	// an empty `type`. This is the input the bundle path accepts.
	bundleJSON := []byte(`{
  "schema_version": "obs.v0.1",
  "snapshots": [
    {
      "captured_at": "2026-01-01T00:00:00Z",
      "source": "deployed",
      "assets": [
        {"id": "bkt-1", "type": "", "vendor": "aws", "properties": {"public": true}}
      ]
    }
  ]
}`)

	// Byte-identical per-timestamp document (the bundle entry hoisted
	// to a standalone obs.v0.1 file). The strict directory validator
	// must reject this for type minLength:1.
	perTimestampJSON := []byte(`{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "source": "deployed",
  "assets": [
    {"id": "bkt-1", "type": "", "vendor": "aws", "properties": {"public": true}}
  ]
}`)

	// First, establish the reference behavior: the strict single-file
	// directory path rejects the empty-type asset. If this somehow
	// does NOT error, the premise of the bug is wrong and we should
	// know about it.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.json"), perTimestampJSON, 0o644); err != nil {
		t.Fatalf("write per-timestamp fixture: %v", err)
	}
	loader := NewObservationLoader()
	if _, _, err := loader.process(perTimestampJSON, filepath.Join(dir, "snapshot.json")); err == nil {
		t.Fatalf("premise broken: strict single-file path accepted empty-type asset (expected schema-validation error)")
	} else if !strings.Contains(err.Error(), "type") && !strings.Contains(strings.ToLower(err.Error()), "schema") {
		// Not fatal to the gate, but record it: we expect the strict
		// path to complain about the type / schema.
		t.Logf("strict path rejected document but message did not mention type/schema: %v", err)
	}

	// Core assertion of CORRECT behavior: the bundle path MUST also
	// reject the empty-type asset, so the two intake paths agree.
	snaps, err := ParseBundle(bundleJSON)
	if err == nil {
		// Surface the observed wrong shape to make the red output
		// self-explanatory.
		gotType := "<no assets>"
		if len(snaps) == 1 && len(snaps[0].Assets) == 1 {
			gotType = string(snaps[0].Assets[0].Type)
		}
		t.Fatalf("ParseBundle accepted an asset with empty type (got Type=%q); "+
			"the strict single-file path rejects the byte-identical document, so the "+
			"bundle path must reject it too to preserve the same-shape invariant", gotType)
	}
}

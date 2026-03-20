package validator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoldenSchemaFiles_ObservationsAccepted walks testdata/schemas/obs/ and
// validates every .json file against the observation schema. If a file exists
// in the golden directory but the validator rejects it, the test fails.
func TestGoldenSchemaFiles_ObservationsAccepted(t *testing.T) {
	root := findRepoRoot(t)
	dir := filepath.Join(root, "testdata", "schemas", "obs")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read golden obs dir: %v", err)
	}

	v := New()
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		found++
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", entry.Name(), err)
			}
			result, err := v.ValidateObservationJSON(data)
			if err != nil {
				t.Fatalf("validate %s: %v", entry.Name(), err)
			}
			if result.HasErrors() {
				t.Errorf("golden file %s rejected by validator:\n%s", entry.Name(), result)
			}
		})
	}
	if found == 0 {
		t.Fatal("no .json files found in testdata/schemas/obs/ — golden files missing")
	}
}

// TestGoldenSchemaFiles_ControlsAccepted walks testdata/schemas/ctrl/ and
// validates every .yaml file against the control schema.
func TestGoldenSchemaFiles_ControlsAccepted(t *testing.T) {
	root := findRepoRoot(t)
	dir := filepath.Join(root, "testdata", "schemas", "ctrl")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read golden ctrl dir: %v", err)
	}

	v := New()
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		found++
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", entry.Name(), err)
			}
			result, err := v.ValidateControlYAML(data)
			if err != nil {
				t.Fatalf("validate %s: %v", entry.Name(), err)
			}
			if result.HasErrors() {
				t.Errorf("golden file %s rejected by validator:\n%s", entry.Name(), result)
			}
		})
	}
	if found == 0 {
		t.Fatal("no .yaml files found in testdata/schemas/ctrl/ — golden files missing")
	}
}

// TestGhostSchemaVersions_Rejected ensures deprecated, future, and malformed
// schema versions are correctly rejected with UNSUPPORTED_SCHEMA_VERSION.
func TestGhostSchemaVersions_Rejected(t *testing.T) {
	v := New()

	obsGhosts := []struct {
		name    string
		version string
	}{
		{"deprecated v0.0", "obs.v0.0"},
		{"future v2", "obs.v2"},
		{"future v99", "obs.v99"},
		{"wrong kind", "ctrl.v1"},
		{"empty version", ""},
		{"garbage", "not-a-version"},
		{"numeric only", "42"},
		{"with prerelease", "obs.v0.1-rc.1"},
		{"with metadata", "obs.v0.1+build.123"},
	}

	for _, tc := range obsGhosts {
		t.Run("obs/"+tc.name, func(t *testing.T) {
			doc := []byte(`{"schema_version":"` + tc.version + `","captured_at":"2026-01-15T00:00:00Z","assets":[]}`)
			result, err := v.ValidateObservationJSON(doc)
			if err != nil {
				t.Fatalf("validate error: %v", err)
			}
			if !result.HasErrors() && !result.HasWarnings() {
				t.Errorf("ghost version %q was accepted — expected rejection", tc.version)
			}
		})
	}

	ctrlGhosts := []struct {
		name    string
		version string
	}{
		{"deprecated v0", "ctrl.v0"},
		{"future v99", "ctrl.v99"},
		{"wrong kind", "obs.v0.1"},
		{"empty version", ""},
		{"garbage", "not-a-version"},
		{"with prerelease", "ctrl.v1-beta"},
	}

	for _, tc := range ctrlGhosts {
		t.Run("ctrl/"+tc.name, func(t *testing.T) {
			doc := []byte("dsl_version: " + tc.version + "\nid: CTL.GHOST.001\nname: Ghost\ndescription: Ghost control\ntype: unsafe_state\nunsafe_predicate:\n  any:\n    - field: properties.x\n      op: eq\n      value: true\n")
			result, err := v.ValidateControlYAML(doc)
			if err != nil {
				t.Fatalf("validate error: %v", err)
			}
			if !result.HasErrors() && !result.HasWarnings() {
				t.Errorf("ghost version %q was accepted — expected rejection", tc.version)
			}
		})
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

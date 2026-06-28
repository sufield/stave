package observations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt_ListObservationFiles_JSONCase(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stave-json-case-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a .json file and a .JSON file
	file1 := filepath.Join(tmpDir, "snap1.json")
	file2 := filepath.Join(tmpDir, "snap2.JSON")
	file3 := filepath.Join(tmpDir, "snap3.Json")

	if err = os.WriteFile(file1, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err = os.WriteFile(file2, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}
	if err = os.WriteFile(file3, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write file3: %v", err)
	}

	entries, err := listObservationFiles(tmpDir)
	if err != nil {
		t.Fatalf("listObservationFiles failed: %v", err)
	}

	// In the original code, only snap1.json is loaded because strings.HasSuffix is case-sensitive.
	// We expect all 3 files to be returned.
	expected := 3
	if len(entries) != expected {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected %d entries, got %d (found: %v)", expected, len(entries), names)
	}
}

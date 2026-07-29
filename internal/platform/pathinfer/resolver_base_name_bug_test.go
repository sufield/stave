package pathinfer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnique_BaseDirMatchingNameCandidate(t *testing.T) {
	// Create a temp directory named "controls"
	tmp := t.TempDir()
	base := filepath.Join(tmp, "controls")
	if err := os.MkdirAll(filepath.Join(base, "s3"), 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	// Calling Unique with base=".../controls" and name="controls"
	// should recognize base itself as the matching candidate, rather than failing with ErrNoCandidate.
	got, _, err := Unique(base, "controls", 2)
	if err != nil {
		t.Fatalf("expected Unique to find base directory matching name, got error: %v", err)
	}
	if got != base {
		t.Errorf("expected %q, got %q", base, got)
	}
}

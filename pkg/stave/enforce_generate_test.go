package stave

import "testing"

// These exercise the enforce-generate helpers that moved here from
// cmd/enforce/generate.

func TestEnforceTargetNames_Empty(t *testing.T) {
	if names := enforceTargetNames(nil); len(names) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(names))
	}
}

func TestEnforceValidateInputPath_Missing(t *testing.T) {
	if err := enforceValidateInputPath("/nonexistent/path/file.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEnforceValidateInputPath_Dir(t *testing.T) {
	if err := enforceValidateInputPath(t.TempDir()); err == nil {
		t.Fatal("expected error for directory input")
	}
}

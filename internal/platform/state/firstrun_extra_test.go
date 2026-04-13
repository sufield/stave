package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/env"
)

func TestFirstRunMarkerPath_DefaultPath(t *testing.T) {
	// Ensure the env override is not set so we exercise the default path.
	t.Setenv(env.FirstRunHintFile.Name, "")

	got, err := FirstRunMarkerPath()
	if err != nil {
		// os.UserConfigDir() may fail in some CI environments; skip if so.
		t.Skipf("UserConfigDir() failed (expected in restricted env): %v", err)
	}
	// The default path must contain "stave" and ".first_run_seen".
	if !strings.Contains(got, "stave") {
		t.Errorf("default marker path %q should contain 'stave'", got)
	}
	if !strings.Contains(got, ".first_run_seen") {
		t.Errorf("default marker path %q should contain '.first_run_seen'", got)
	}
	// Must be an absolute path.
	if !filepath.IsAbs(got) {
		t.Errorf("default marker path %q should be absolute", got)
	}
}

func TestFirstRunMarkerPath_OverrideWithSpaces(t *testing.T) {
	// Leading/trailing whitespace in the env var must be trimmed.
	want := filepath.Join(t.TempDir(), "marker")
	t.Setenv(env.FirstRunHintFile.Name, "  "+want+"  ")
	got, err := FirstRunMarkerPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("FirstRunMarkerPath() = %q, want %q", got, want)
	}
}

func TestMarkFirstRunSeen_CreatesParentDirs(t *testing.T) {
	// Verify that deeply nested parent directories are created.
	base := t.TempDir()
	path := filepath.Join(base, "deep", "nested", "dirs", ".first_run_seen")
	if err := MarkFirstRunSeen(path); err != nil {
		t.Fatalf("MarkFirstRunSeen failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected marker file at %s: %v", path, err)
	}
	// File should be readable.
	data, err := os.ReadFile(path) //nolint:gosec // test-only path
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "seen\n" {
		t.Errorf("marker content = %q, want 'seen\\n'", data)
	}
}

package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/envvar"
)

func TestFirstRunMarkerPath_Override(t *testing.T) {
	want := filepath.Join(t.TempDir(), "marker")
	t.Setenv(envvar.FirstRunHintFile.Name, want)
	got, err := FirstRunMarkerPath()
	if err != nil {
		t.Fatalf("FirstRunMarkerPath error: %v", err)
	}
	if got != want {
		t.Fatalf("marker path = %q, want %q", got, want)
	}
}

func TestMarkFirstRunSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stave", ".first_run_seen")
	if err := MarkFirstRunSeen(path); err != nil {
		t.Fatalf("MarkFirstRunSeen failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected marker file to exist: %v", err)
	}
}

func TestMarkFirstRunSeen_SkipsIfExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".first_run_seen")

	// Create the marker file first.
	if err := os.WriteFile(path, []byte("seen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info1, _ := os.Stat(path)

	// Second call should be a no-op.
	if err := MarkFirstRunSeen(path); err != nil {
		t.Fatalf("MarkFirstRunSeen failed: %v", err)
	}
	info2, _ := os.Stat(path)

	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Fatal("expected marker file to remain unchanged on second call")
	}
}

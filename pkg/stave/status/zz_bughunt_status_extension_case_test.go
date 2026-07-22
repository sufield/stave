package status

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt_Inspector_ExtensionCase(t *testing.T) {
	root := t.TempDir()
	ctlDir := filepath.Join(root, "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	obsDir := filepath.Join(root, "observations")
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write uppercase extension files
	if err := os.WriteFile(filepath.Join(ctlDir, "control.YAML"), []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(obsDir, "observation.JSON"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	in := NewInspector()
	state, err := in.Inspect(root)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// We expect 1 control and 1 observation to be found case-insensitively
	if state.Controls.Count != 1 {
		t.Errorf("Controls.Count=%d, want 1 (case-insensitive)", state.Controls.Count)
	}
	if state.Observations.Count != 1 {
		t.Errorf("Observations.Count=%d, want 1 (case-insensitive)", state.Observations.Count)
	}
}

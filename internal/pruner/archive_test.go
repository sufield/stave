package pruner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyArchive(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "obs")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir obs: %v", err)
	}
	src := filepath.Join(srcDir, "a.json")
	if err := os.WriteFile(src, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	archiveDir := filepath.Join(tmp, "archive")
	dst := filepath.Join(archiveDir, "a.json")
	res, err := ApplyArchive(ArchiveInput{
		ArchiveDir: archiveDir,
		Moves: []ArchiveMove{
			{Src: src, Dst: dst},
		},
		Options: MoveOptions{},
	})
	if err != nil {
		t.Fatalf("ApplyArchive() error = %v", err)
	}
	if res.Archived != 1 {
		t.Fatalf("archived = %d, want 1", res.Archived)
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("expected src removed, stat err=%v", statErr)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("dst content = %q", string(data))
	}
}

package plan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySnapshotPlan_Delete(t *testing.T) {
	tmp := t.TempDir()
	obsRoot := filepath.Join(tmp, "observations")
	if err := os.MkdirAll(obsRoot, 0o755); err != nil {
		t.Fatalf("mkdir observations: %v", err)
	}
	target := filepath.Join(obsRoot, "old.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	res, err := ApplySnapshotPlan(SnapshotPlanApplyInput{
		Entries: []PlanEntry{
			{RelPath: "old.json", Action: ActionPrune},
		},
		ObservationsRoot: obsRoot,
	})
	if err != nil {
		t.Fatalf("ApplySnapshotPlan() error = %v", err)
	}
	if res.Applied != 1 || res.Deleted != 1 || res.Archived != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("expected target removed, stat err=%v", statErr)
	}
}

func TestApplySnapshotPlan_Archive(t *testing.T) {
	tmp := t.TempDir()
	obsRoot := filepath.Join(tmp, "observations")
	if err := os.MkdirAll(obsRoot, 0o755); err != nil {
		t.Fatalf("mkdir observations: %v", err)
	}
	src := filepath.Join(obsRoot, "nested", "old.json")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir src parent: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"v":1}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	archiveDir := filepath.Join(tmp, "archive")
	res, err := ApplySnapshotPlan(SnapshotPlanApplyInput{
		Entries: []PlanEntry{
			{RelPath: filepath.Join("nested", "old.json"), Action: ActionArchive},
		},
		ObservationsRoot: obsRoot,
		ArchiveDir:       archiveDir,
	})
	if err != nil {
		t.Fatalf("ApplySnapshotPlan() error = %v", err)
	}
	if res.Applied != 1 || res.Archived != 1 || res.Deleted != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	dst := filepath.Join(archiveDir, "nested", "old.json")
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("expected src removed, stat err=%v", statErr)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != `{"v":1}` {
		t.Fatalf("dst content = %q", string(data))
	}
}

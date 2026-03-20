package archive

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/pruner"
	"github.com/sufield/stave/internal/pruner/fsops"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

func moveSnapshotFile(src, dst string) error {
	return fsops.MoveSnapshotFile(src, dst, fsops.MoveOptions{})
}

func TestPlanPruneForArchive_RespectsKeepMin(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{Name: "a.json", CapturedAt: now.AddDate(0, 0, -40)},
		{Name: "b.json", CapturedAt: now.AddDate(0, 0, -35)},
		{Name: "c.json", CapturedAt: now.AddDate(0, 0, -20)},
		{Name: "d.json", CapturedAt: now.AddDate(0, 0, -5)},
	}

	moves := pruneshared.PlanPrune(files, retention.Criteria{Now: now, OlderThan: 30 * 24 * time.Hour, KeepMin: 2})
	if len(moves) != 2 {
		t.Fatalf("expected 2 archive moves, got %d", len(moves))
	}
	if moves[0].Name != "a.json" || moves[1].Name != "b.json" {
		t.Fatalf("expected oldest files first, got %s and %s", moves[0].Name, moves[1].Name)
	}
}

func TestMoveSnapshotFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.json")
	dst := filepath.Join(tmp, "archive", "dst.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir dst dir: %v", err)
	}
	if err := os.WriteFile(src, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := moveSnapshotFile(src, dst); err != nil {
		t.Fatalf("moveSnapshotFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("expected src to be removed, stat err=%v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Fatalf("unexpected dst content: %q", string(data))
	}
}

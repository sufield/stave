package snapshot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/pruner"
)

// testListRecursive is a test helper that creates a loader and delegates.
func testListRecursive(ctx context.Context, dir string, excludeDirs []string) ([]pruner.SnapshotFile, error) {
	loader, err := compose.ActiveProvider().NewSnapshotRepo()
	if err != nil {
		return nil, err
	}
	return listSnapshotFilesRecursive(ctx, loader, dir, excludeDirs)
}

// writeTestObservation writes a minimal valid observation JSON to the given path.
func writeTestObservation(t *testing.T, path string, capturedAt time.Time) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	content := fmt.Sprintf(`{
  "schema_version": "obs.v0.1",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
    "tool": "test"
  },
  "captured_at": %q,
  "assets": [
    {
      "id": "aws:s3:::test-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "access": {
            "public_read": false,
            "public_list": false
          }
        }
      }
    }
  ]
}`, capturedAt.Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestListObservationSnapshotFilesRecursive_FlatDir(t *testing.T) {
	root := t.TempDir()
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "2026-01-10.json"), t1)
	writeTestObservation(t, filepath.Join(root, "2026-01-11.json"), t2)

	files, err := testListRecursive(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if files[0].RelPath != "2026-01-10.json" {
		t.Fatalf("files[0].RelPath=%q, want 2026-01-10.json", files[0].RelPath)
	}
	if files[1].RelPath != "2026-01-11.json" {
		t.Fatalf("files[1].RelPath=%q, want 2026-01-11.json", files[1].RelPath)
	}
}

func TestListObservationSnapshotFilesRecursive_NestedDirs(t *testing.T) {
	root := t.TempDir()
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "prod", "2026-01-10.json"), t1)
	writeTestObservation(t, filepath.Join(root, "dev", "2026-01-11.json"), t2)
	writeTestObservation(t, filepath.Join(root, "prod", "sub", "2026-01-12.json"), t3)

	files, err := testListRecursive(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	// Sorted by captured_at
	if files[0].RelPath != "prod/2026-01-10.json" {
		t.Fatalf("files[0].RelPath=%q", files[0].RelPath)
	}
	if files[1].RelPath != "dev/2026-01-11.json" {
		t.Fatalf("files[1].RelPath=%q", files[1].RelPath)
	}
	if files[2].RelPath != "prod/sub/2026-01-12.json" {
		t.Fatalf("files[2].RelPath=%q", files[2].RelPath)
	}
}

func TestListObservationSnapshotFilesRecursive_SkipsUnderscoreDirs(t *testing.T) {
	root := t.TempDir()
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "prod", "2026-01-10.json"), t1)
	writeTestObservation(t, filepath.Join(root, "_staging", "2026-01-11.json"), t2)

	files, err := testListRecursive(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (skipping _staging), got %d", len(files))
	}
	if files[0].RelPath != "prod/2026-01-10.json" {
		t.Fatalf("files[0].RelPath=%q", files[0].RelPath)
	}
}

func TestListObservationSnapshotFilesRecursive_ExcludeDirs(t *testing.T) {
	root := t.TempDir()
	archiveDir := filepath.Join(root, "archive")
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "prod", "2026-01-10.json"), t1)
	writeTestObservation(t, filepath.Join(archiveDir, "2026-01-11.json"), t2)

	files, err := testListRecursive(context.Background(), root, []string{archiveDir})
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (excluding archive), got %d", len(files))
	}
	if files[0].RelPath != "prod/2026-01-10.json" {
		t.Fatalf("files[0].RelPath=%q", files[0].RelPath)
	}
}

func TestListObservationSnapshotFilesRecursive_RelPathUsesForwardSlashes(t *testing.T) {
	root := t.TempDir()
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "env", "region", "2026-01-10.json"), t1)

	files, err := testListRecursive(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if strings.Contains(files[0].RelPath, "\\") {
		t.Fatalf("RelPath contains backslash: %q", files[0].RelPath)
	}
	if files[0].RelPath != "env/region/2026-01-10.json" {
		t.Fatalf("RelPath=%q, want env/region/2026-01-10.json", files[0].RelPath)
	}
}

func TestListObservationSnapshotFilesRecursive_SortedByCapturedAt(t *testing.T) {
	root := t.TempDir()
	// Write in reverse chronological order
	t3 := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	writeTestObservation(t, filepath.Join(root, "c.json"), t3)
	writeTestObservation(t, filepath.Join(root, "a.json"), t1)
	writeTestObservation(t, filepath.Join(root, "b.json"), t2)

	files, err := testListRecursive(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("recursive list: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
	if !files[0].CapturedAt.Before(files[1].CapturedAt) || !files[1].CapturedAt.Before(files[2].CapturedAt) {
		t.Fatalf("files not sorted by captured_at: %v, %v, %v",
			files[0].CapturedAt, files[1].CapturedAt, files[2].CapturedAt)
	}
}

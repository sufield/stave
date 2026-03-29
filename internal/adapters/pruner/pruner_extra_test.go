package pruner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupAction_ModeString(t *testing.T) {
	tests := []struct {
		action CleanupAction
		dryRun bool
		want   string
	}{
		{ActionDelete, false, "DELETE"},
		{ActionMove, false, "MOVE"},
		{ActionDelete, true, "DRY_RUN"},
		{ActionMove, true, "DRY_RUN"},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%s/dryRun=%v", tt.action, tt.dryRun)
		t.Run(name, func(t *testing.T) {
			got := tt.action.ModeString(tt.dryRun)
			if got != tt.want {
				t.Fatalf("ModeString()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestScannerOptions_MaxFiles_Default(t *testing.T) {
	opts := ScannerOptions{}
	if got := opts.maxFiles(); got != DefaultMaxFiles {
		t.Fatalf("maxFiles()=%d, want %d", got, DefaultMaxFiles)
	}
}

func TestScannerOptions_MaxFiles_Custom(t *testing.T) {
	opts := ScannerOptions{MaxFiles: 50}
	if got := opts.maxFiles(); got != 50 {
		t.Fatalf("maxFiles()=%d, want 50", got)
	}
}

func TestListSnapshotFilesFlat_NilMetadataLoader(t *testing.T) {
	dir := t.TempDir()
	_, err := ListSnapshotFilesFlat(context.Background(), dir, ScannerOptions{})
	if err == nil {
		t.Fatal("expected error for nil MetadataLoader")
	}
}

func TestListSnapshotFilesFlat_NonexistentDir(t *testing.T) {
	_, err := ListSnapshotFilesFlat(context.Background(), "/nonexistent", ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return time.Time{}, nil },
	})
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestListSnapshotFilesFlat_SortsByCapturedAt(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create files in reverse time order.
	for i, name := range []string{"obs-c.json", "obs-b.json", "obs-a.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = i
	}

	files, err := ListSnapshotFilesFlat(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) {
			switch name {
			case "obs-a.json":
				return base.Add(3 * time.Hour), nil
			case "obs-b.json":
				return base.Add(1 * time.Hour), nil
			case "obs-c.json":
				return base.Add(2 * time.Hour), nil
			}
			return time.Time{}, fmt.Errorf("unknown: %s", name)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("len=%d, want 3", len(files))
	}
	// Should be sorted by CapturedAt ascending.
	if files[0].Name != "obs-b.json" {
		t.Fatalf("files[0]=%q, want obs-b.json (earliest)", files[0].Name)
	}
	if files[1].Name != "obs-c.json" {
		t.Fatalf("files[1]=%q, want obs-c.json", files[1].Name)
	}
	if files[2].Name != "obs-a.json" {
		t.Fatalf("files[2]=%q, want obs-a.json (latest)", files[2].Name)
	}
}

func TestListSnapshotFilesFlat_SkipsDirectoriesAndNonJSON(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create a JSON file, a non-JSON file, and a subdirectory.
	if err := os.WriteFile(filepath.Join(dir, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	files, err := ListSnapshotFilesFlat(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1 (only .json)", len(files))
	}
}

func TestListSnapshotFilesFlat_MetadataLoaderError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ListSnapshotFilesFlat(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) {
			return time.Time{}, fmt.Errorf("parse error")
		},
	})
	if err == nil {
		t.Fatal("expected error from metadata loader")
	}
}

func TestListSnapshotFilesFlat_CancelledContext(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		name := fmt.Sprintf("obs-%04d.json", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := ListSnapshotFilesFlat(ctx, dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
	})
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestListSnapshotFilesRecursive_NilMetadataLoader(t *testing.T) {
	dir := t.TempDir()
	_, err := ListSnapshotFilesRecursive(context.Background(), dir, ScannerOptions{})
	if err == nil {
		t.Fatal("expected error for nil MetadataLoader")
	}
}

func TestListSnapshotFilesRecursive_SkipsUnderscoreDirs(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create a normal dir and an underscore dir.
	normalDir := filepath.Join(dir, "env1")
	skipDir := filepath.Join(dir, "_archive")
	if err := os.MkdirAll(normalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(skipDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(normalDir, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "archived.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := ListSnapshotFilesRecursive(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1 (underscore dir should be skipped)", len(files))
	}
}

func TestListSnapshotFilesRecursive_ExcludeDirs(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	subA := filepath.Join(dir, "a")
	subB := filepath.Join(dir, "b")
	for _, d := range []string{subA, subB} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "obs.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := ListSnapshotFilesRecursive(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
		ExcludeDirs:    []string{subB},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1 (subB excluded)", len(files))
	}
}

func TestListSnapshotFilesRecursive_RelPathUsesForwardSlashes(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	sub := filepath.Join(dir, "nested", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := ListSnapshotFilesRecursive(context.Background(), dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1", len(files))
	}
	want := "nested/deep/obs.json"
	if files[0].RelPath != want {
		t.Fatalf("RelPath=%q, want %q", files[0].RelPath, want)
	}
}

func TestListSnapshotFilesRecursive_CancelledContext(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sub := filepath.Join(dir, "env")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ListSnapshotFilesRecursive(ctx, dir, ScannerOptions{
		MetadataLoader: func(path, name string) (time.Time, error) { return base, nil },
	})
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestSnapshotLimitError(t *testing.T) {
	err := snapshotLimitError("/obs", 100)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, ErrTooManySnapshots) {
		t.Fatalf("expected ErrTooManySnapshots, got: %v", err)
	}
}

func TestIsSnapshotFile(t *testing.T) {
	// We can only test this indirectly through ListSnapshotFilesFlat behavior.
	// Non-JSON files should be skipped, which is tested above.
}

func TestListSnapshotFilesFlatWithLoader_NilLoader(t *testing.T) {
	dir := t.TempDir()
	_, err := ListSnapshotFilesFlatWithLoader(context.Background(), dir, nil)
	if err == nil {
		t.Fatal("expected error for nil loader")
	}
}

func TestListSnapshotFilesRecursiveWithLoader_NilLoader(t *testing.T) {
	dir := t.TempDir()
	_, err := ListSnapshotFilesRecursiveWithLoader(context.Background(), dir, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil loader")
	}
}

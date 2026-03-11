package pruner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListSnapshotFilesFlat_RejectsExcessiveFileCount(t *testing.T) {
	old := maxSnapshotFiles
	maxSnapshotFiles = 3
	t.Cleanup(func() { maxSnapshotFiles = old })

	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 4 {
		name := fmt.Sprintf("obs-%04d.json", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	loader := func(path, name string) (time.Time, error) {
		return base, nil
	}

	_, err := ListSnapshotFilesFlat(dir, loader)
	if err == nil {
		t.Fatal("expected ErrTooManySnapshots")
	}
	if !errors.Is(err, ErrTooManySnapshots) {
		t.Fatalf("expected ErrTooManySnapshots, got: %v", err)
	}
}

func TestListSnapshotFilesFlat_AcceptsWithinLimit(t *testing.T) {
	old := maxSnapshotFiles
	maxSnapshotFiles = 3
	t.Cleanup(func() { maxSnapshotFiles = old })

	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 3 {
		name := fmt.Sprintf("obs-%04d.json", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	loader := func(path, name string) (time.Time, error) {
		return base.Add(time.Duration(name[4]-'0') * time.Hour), nil
	}

	files, err := ListSnapshotFilesFlat(dir, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 files, got %d", len(files))
	}
}

func TestListSnapshotFilesRecursive_RejectsExcessiveFileCount(t *testing.T) {
	old := maxSnapshotFiles
	maxSnapshotFiles = 3
	t.Cleanup(func() { maxSnapshotFiles = old })

	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Spread across subdirectories to exercise the recursive walker.
	for i := range 4 {
		sub := filepath.Join(dir, fmt.Sprintf("env%d", i))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
		name := fmt.Sprintf("obs-%04d.json", i)
		if err := os.WriteFile(filepath.Join(sub, name), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	loader := func(path, name string) (time.Time, error) {
		return base, nil
	}

	_, err := ListSnapshotFilesRecursive(dir, nil, loader)
	if err == nil {
		t.Fatal("expected ErrTooManySnapshots")
	}
	if !errors.Is(err, ErrTooManySnapshots) {
		t.Fatalf("expected ErrTooManySnapshots, got: %v", err)
	}
}

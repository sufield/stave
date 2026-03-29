package pruner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

type stubSnapshotReader struct {
	capturedAt time.Time
	err        error
}

func (s *stubSnapshotReader) LoadSnapshotFromReader(_ context.Context, _ io.Reader, _ string) (asset.Snapshot, error) {
	if s.err != nil {
		return asset.Snapshot{}, s.err
	}
	return asset.Snapshot{
		SchemaVersion: kernel.Schema("obs.v0.1"),
		CapturedAt:    s.capturedAt,
	}, nil
}

func TestLoadSnapshotCapturedAt_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obs.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	loader := &stubSnapshotReader{capturedAt: ts}

	got, err := loadSnapshotCapturedAt(context.Background(), loader, path, "obs.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(ts) {
		t.Fatalf("got %v, want %v", got, ts)
	}
}

func TestLoadSnapshotCapturedAt_LoaderError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obs.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := &stubSnapshotReader{err: fmt.Errorf("parse failure")}
	_, err := loadSnapshotCapturedAt(context.Background(), loader, path, "obs.json")
	if err == nil {
		t.Fatal("expected error from loader")
	}
}

func TestLoadSnapshotCapturedAt_FileNotFound(t *testing.T) {
	loader := &stubSnapshotReader{}
	_, err := loadSnapshotCapturedAt(context.Background(), loader, "/nonexistent/obs.json", "obs.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadSnapshotCapturedAt_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	loader := &stubSnapshotReader{}
	_, err := loadSnapshotCapturedAt(ctx, loader, "/whatever", "obs.json")
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestListSnapshotFilesFlatWithLoader_Success(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(dir, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := &stubSnapshotReader{capturedAt: ts}
	files, err := ListSnapshotFilesFlatWithLoader(context.Background(), dir, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1", len(files))
	}
	if files[0].Name != "obs.json" {
		t.Fatalf("name=%q, want obs.json", files[0].Name)
	}
}

func TestListSnapshotFilesRecursiveWithLoader_Success(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	sub := filepath.Join(dir, "env1")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "obs.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := &stubSnapshotReader{capturedAt: ts}
	files, err := ListSnapshotFilesRecursiveWithLoader(context.Background(), dir, nil, loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d, want 1", len(files))
	}
}

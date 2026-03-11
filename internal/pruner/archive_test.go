package pruner

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sufield/stave/internal/platform/fsutil"
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

func TestApplyArchive_RejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "obs")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir obs: %v", err)
	}
	src := filepath.Join(srcDir, "a.json")
	if err := os.WriteFile(src, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	archiveDir := filepath.Join(tmp, "archive")
	// Destination escapes archive directory via ..
	escapedDst := filepath.Join(archiveDir, "..", "escaped.json")

	_, err := ApplyArchive(ArchiveInput{
		ArchiveDir: archiveDir,
		Moves: []ArchiveMove{
			{Src: src, Dst: escapedDst},
		},
		Options: MoveOptions{Overwrite: true},
	})
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !errors.Is(err, fsutil.ErrPathTraversal) {
		t.Fatalf("expected ErrPathTraversal, got: %v", err)
	}
}

func TestMoveSnapshotFile_NoOverwrite_RejectsExisting(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.json")
	dst := filepath.Join(tmp, "dst.json")
	if err := os.WriteFile(src, []byte(`{"src":true}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, []byte(`{"dst":true}`), 0o644); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	err := MoveSnapshotFile(src, dst, MoveOptions{Overwrite: false})
	if err == nil {
		t.Fatal("expected overwrite error")
	}
	if !errors.Is(err, fsutil.ErrFileExists) {
		t.Fatalf("expected ErrFileExists, got: %v", err)
	}

	// Source should remain untouched.
	data, readErr := os.ReadFile(src)
	if readErr != nil {
		t.Fatalf("source should still exist: %v", readErr)
	}
	if string(data) != `{"src":true}` {
		t.Fatalf("source content changed: %q", string(data))
	}
	// Destination should remain untouched.
	data, readErr = os.ReadFile(dst)
	if readErr != nil {
		t.Fatalf("dst should still exist: %v", readErr)
	}
	if string(data) != `{"dst":true}` {
		t.Fatalf("destination content changed: %q", string(data))
	}
}

func TestMoveSnapshotFile_Overwrite_Replaces(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.json")
	dst := filepath.Join(tmp, "dst.json")
	if err := os.WriteFile(src, []byte(`{"new":true}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, []byte(`{"old":true}`), 0o644); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := MoveSnapshotFile(src, dst, MoveOptions{Overwrite: true}); err != nil {
		t.Fatalf("MoveSnapshotFile: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != `{"new":true}` {
		t.Fatalf("dst content = %q, want new", string(data))
	}
	if _, statErr := os.Stat(src); !os.IsNotExist(statErr) {
		t.Fatalf("src should be removed, stat err=%v", statErr)
	}
}

func TestMoveSnapshotFile_RejectsSourceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmp := t.TempDir()
	real := filepath.Join(tmp, "real.json")
	if err := os.WriteFile(real, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}
	src := filepath.Join(tmp, "link.json")
	if err := os.Symlink(real, src); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	dst := filepath.Join(tmp, "dst.json")

	err := MoveSnapshotFile(src, dst, MoveOptions{AllowSymlink: false})
	if err == nil {
		t.Fatal("expected symlink error for source")
	}
	if !errors.Is(err, fsutil.ErrSymlinkForbidden) {
		t.Fatalf("expected ErrSymlinkForbidden, got: %v", err)
	}
}

func TestMoveSnapshotFile_RejectsDestSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.json")
	if err := os.WriteFile(src, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	target := filepath.Join(tmp, "target.json")
	if err := os.WriteFile(target, []byte(`{"target":true}`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	dst := filepath.Join(tmp, "link.json")
	if err := os.Symlink(target, dst); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := MoveSnapshotFile(src, dst, MoveOptions{AllowSymlink: false, Overwrite: true})
	if err == nil {
		t.Fatal("expected symlink error for destination")
	}
	if !errors.Is(err, fsutil.ErrSymlinkForbidden) {
		t.Fatalf("expected ErrSymlinkForbidden, got: %v", err)
	}
}

func TestMoveSnapshotFile_PreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits differ on Windows")
	}

	tmp := t.TempDir()
	// Use two separate temp dirs to force the cross-device copy path.
	// On the same filesystem os.Link/os.Rename succeeds, so we simulate
	// the copy fallback by calling crossDeviceMove directly.
	src := filepath.Join(tmp, "src.json")
	if err := os.WriteFile(src, []byte(`{"ok":true}`), 0o640); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(tmp, "dst.json")

	if err := crossDeviceMove(src, dst, MoveOptions{Overwrite: true}); err != nil {
		t.Fatalf("crossDeviceMove: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Fatalf("dst permissions = %o, want 0640", perm)
	}
}

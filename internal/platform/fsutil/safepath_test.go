package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeDir_RejectsParentTraversal(t *testing.T) {
	cwd, _ := os.Getwd()
	_, err := SafeDir("../../../etc/passwd", cwd)
	if err == nil {
		t.Error("expected error for parent traversal")
	}
}

func TestSafeDir_AcceptsSubdirectory(t *testing.T) {
	cwd, _ := os.Getwd()
	abs, err := SafeDir("testdata/sub", cwd)
	if err != nil {
		t.Errorf("expected no error for subdirectory, got: %v", err)
	}
	if abs == "" {
		t.Error("expected non-empty resolved path")
	}
}

func TestSafeDir_AcceptsCurrentDir(t *testing.T) {
	cwd, _ := os.Getwd()
	_, err := SafeDir(".", cwd)
	if err != nil {
		t.Errorf("expected no error for current dir, got: %v", err)
	}
}

func TestSafeDir_RejectsSymlinkEscape(t *testing.T) {
	// base/link -> outside. "link" is lexically inside base, so the
	// Abs+Rel check passes; only symlink resolution catches the escape.
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := SafeDir("link", base); err == nil {
		t.Fatal("expected error for in-base symlink pointing outside base, got nil")
	}
}

func TestSafeDir_RejectsEscapeThroughSymlinkedAncestor(t *testing.T) {
	// base/link -> outside; target "link/secret" descends through the
	// symlink to a file outside base.
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := SafeDir(filepath.Join("link", "secret"), base); err == nil {
		t.Fatal("expected error for path descending through symlinked ancestor, got nil")
	}
}

func TestSafeDir_AcceptsRealSubdirWhenBaseItselfSymlinked(t *testing.T) {
	// base is reached via a symlink (e.g. macOS /tmp -> /private/tmp).
	// A genuine subdirectory must still be accepted: both sides resolve
	// consistently, so containment holds.
	realBase := t.TempDir()
	if err := os.MkdirAll(filepath.Join(realBase, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkedBase := filepath.Join(t.TempDir(), "baselink")
	if err := os.Symlink(realBase, linkedBase); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// path is absolute and genuinely under the symlinked base; both
	// sides resolve to realBase, so containment must hold.
	if _, err := SafeDir(filepath.Join(linkedBase, "sub"), linkedBase); err != nil {
		t.Errorf("genuine subdir under symlinked base must be accepted, got: %v", err)
	}
}

func TestJoinWithinRoot_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "control.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// "link/control.yaml" is lexically within root but resolves outside.
	_, err := JoinWithinRoot(root, filepath.Join("link", "control.yaml"))
	if err == nil {
		t.Fatal("expected error for registry entry resolving outside root, got nil")
	}
	if !errors.Is(err, ErrPathTraversal) {
		t.Errorf("want ErrPathTraversal, got %v", err)
	}
}

func TestJoinWithinRoot_AcceptsGenuineInRootPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "s3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "s3", "control.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := JoinWithinRoot(root, filepath.Join("s3", "control.yaml"))
	if err != nil {
		t.Fatalf("genuine in-root path must be accepted, got: %v", err)
	}
	if got == "" {
		t.Error("expected non-empty joined path")
	}
}

func TestSafeFilename_RejectsForwardSlash(t *testing.T) {
	if err := SafeFilename("foo/bar"); err == nil {
		t.Error("expected error for forward slash")
	}
}

func TestSafeFilename_RejectsBackslash(t *testing.T) {
	if err := SafeFilename(`foo\bar`); err == nil {
		t.Error("expected error for backslash")
	}
}

func TestSafeFilename_AcceptsValidControlID(t *testing.T) {
	if err := SafeFilename("CTL.S3.PUBLIC.001"); err != nil {
		t.Errorf("expected no error for valid control ID, got: %v", err)
	}
}

func TestSafeFilename_RejectsEmpty(t *testing.T) {
	if err := SafeFilename(""); err == nil {
		t.Error("expected error for empty string")
	}
}

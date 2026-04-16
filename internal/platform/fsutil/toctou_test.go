package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSafeMkdirAll_SymlinkInPath_Rejected verifies that SafeMkdirAll
// rejects paths where any component is a symlink. This is the
// deterministic verification of the TOCTOU fix — if SafeMkdirAll
// uses os.Lstat and checks ModeSymlink, this test passes.
func TestSafeMkdirAll_SymlinkInPath_Rejected(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a real directory to be the symlink target.
	realDir := filepath.Join(tmpDir, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Create a symlink as a path component.
	symlinkComponent := filepath.Join(tmpDir, "symlink-component")
	if err := os.Symlink(realDir, symlinkComponent); err != nil {
		t.Fatalf("setup: creating symlink: %v", err)
	}

	// Attempt to create a directory through the symlink component.
	targetPath := filepath.Join(symlinkComponent, "should-not-be-created")

	err := SafeMkdirAll(targetPath, WriteOptions{Perm: 0o755})

	if err == nil {
		redirectedPath := filepath.Join(realDir, "should-not-be-created")
		if _, statErr := os.Stat(redirectedPath); statErr == nil {
			t.Error("VULNERABLE: SafeMkdirAll created directory through symlink " +
				"component at attacker-controlled location")
		}
	} else {
		t.Logf("FIXED: SafeMkdirAll correctly rejected symlink in path: %v", err)
	}
}

// TestSafeMkdirAll_NoSymlink_Succeeds verifies that SafeMkdirAll
// works correctly for normal (non-symlink) paths.
func TestSafeMkdirAll_NoSymlink_Succeeds(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "a", "b", "c")

	err := SafeMkdirAll(targetPath, WriteOptions{Perm: 0o755})
	if err != nil {
		t.Fatalf("SafeMkdirAll failed on normal path: %v", err)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("created path is not a directory")
	}
}

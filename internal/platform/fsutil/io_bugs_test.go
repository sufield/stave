package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Bug 1: LimitedReadAll allocates limit+1 bytes into memory before checking
// ---------------------------------------------------------------------------

func TestLimitedReadAll_AllocatesFullLimitBeforeError(t *testing.T) {
	// When input exceeds the limit, LimitedReadAll uses
	// io.ReadAll(io.LimitReader(r, limit+1)) which reads limit+1 bytes
	// into a byte slice before checking len(data) > limit.
	//
	// This means a 256MB+ stream causes a 256MB allocation even though
	// the function's purpose is to reject oversized input.
	//
	// A safer implementation would use a bounded buffer or io.CopyN to
	// detect oversized input without allocating the full limit.

	// Use a small limit to avoid actual memory pressure in tests.
	origLimit := maxInputFileBytes
	maxInputFileBytes = 1024 // 1KB limit for test
	t.Cleanup(func() { maxInputFileBytes = origLimit })

	// Input is 2x the limit — the current implementation will allocate
	// limit+1 bytes before returning the error.
	oversized := strings.NewReader(strings.Repeat("x", 2048))

	_, err := LimitedReadAll(oversized, "test-stream")
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("expected safety limit error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bug 2: SafeMkdirAll doesn't catch intermediate symlinks
// ---------------------------------------------------------------------------

func TestSafeMkdirAll_IntermediateSymlinkNotDetected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires Unix")
	}

	base := t.TempDir()
	target := t.TempDir()

	// Create a symlink as an intermediate directory component.
	// base/link -> target (a different directory tree)
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	// Ask SafeMkdirAll to create base/link/subdir.
	// CheckSymlinkSafety checks "base/link/subdir" which doesn't exist,
	// then walks up to "base/link" — which IS a symlink and should fail.
	// But os.MkdirAll would follow the symlink and create subdir inside
	// the target directory.
	path := filepath.Join(link, "subdir")
	err := SafeMkdirAll(path, WriteOptions{Perm: 0o755})

	if err == nil {
		// If this passes (no error), the symlink was followed silently.
		// Check if the directory was created in the wrong location.
		if _, statErr := os.Stat(filepath.Join(target, "subdir")); statErr == nil {
			t.Error("SafeMkdirAll followed an intermediate symlink and created a directory in the wrong location")
		}
	}
	// If err != nil, the implementation correctly detected the symlink.
}

// ---------------------------------------------------------------------------
// Bug 3: CheckSymlinkSafety silently succeeds at maxParentWalk depth
// ---------------------------------------------------------------------------

func TestCheckSymlinkSafety_DeepPathExceedsWalkLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("deep path test requires Unix")
	}

	base := t.TempDir()

	// Build a path deeper than maxParentWalk (16 levels).
	// None of the intermediate directories exist.
	parts := make([]string, maxParentWalk+5)
	parts[0] = base
	for i := 1; i < len(parts); i++ {
		parts[i] = "d"
	}
	deepPath := filepath.Join(parts...)

	// Create a symlink at a level above maxParentWalk.
	// CheckSymlinkSafety should either walk all the way to the root
	// or return an error if it hits the walk limit without finding
	// an existing path component.
	err := CheckSymlinkSafety(deepPath)

	// BUG: The current implementation silently returns nil after hitting
	// maxParentWalk without finding an existing ancestor. A correct
	// implementation should return an error — an unresolvable path
	// should not be assumed safe.
	if err == nil {
		t.Error("CheckSymlinkSafety should return an error when walk limit is exhausted without finding an existing ancestor")
	}
}

// ---------------------------------------------------------------------------
// Bug 4: SafeCreateFile TOCTOU window with Overwrite=true
// ---------------------------------------------------------------------------

func TestSafeCreateFile_VerifyHandleClosesRaceWindow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires Unix")
	}

	base := t.TempDir()

	// Create a legitimate file.
	target := filepath.Join(base, "legit.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Overwrite mode uses O_TRUNC which truncates BEFORE verifyHandle runs.
	// If an attacker swaps the file for a symlink between CheckSymlinkSafety
	// and OpenFile, O_TRUNC would truncate the symlink target.
	//
	// Verify that verifyHandle catches inode mismatches by simulating:
	// 1. Open the file normally
	// 2. Replace the path with a symlink to a different file
	// 3. verifyHandle should detect the mismatch

	decoy := filepath.Join(base, "decoy.txt")
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Open the legitimate file
	f, err := os.OpenFile(target, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Swap the path to point to a different file (simulating a race)
	if rmErr := os.Remove(target); rmErr != nil {
		t.Fatal(rmErr)
	}
	if lnErr := os.Symlink(decoy, target); lnErr != nil {
		t.Fatal(lnErr)
	}

	// verifyHandle should detect that the file handle and the path
	// now point to different inodes.
	err = verifyHandle(f, target)
	if err == nil {
		t.Error("verifyHandle should detect inode mismatch after symlink swap")
	}
}

// ---------------------------------------------------------------------------
// Bug 5: JoinWithinRoot with separator-prefixed path on Windows
// ---------------------------------------------------------------------------

func TestJoinWithinRoot_SeparatorPrefixedPath(t *testing.T) {
	root := t.TempDir()

	// On Unix, this is caught by filepath.IsAbs. On Windows, a path
	// like \temp\file is relative to the current drive root and may
	// not be caught by IsAbs depending on the Go version.
	_, err := JoinWithinRoot(root, string(filepath.Separator)+"etc"+string(filepath.Separator)+"passwd")
	if err == nil {
		t.Error("JoinWithinRoot should reject paths starting with separator")
	}
}

// ---------------------------------------------------------------------------
// Bug 6: SafeMkdirAll doesn't check each path component individually
// ---------------------------------------------------------------------------

func TestSafeMkdirAll_SymlinkInMiddleComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires Unix")
	}

	base := t.TempDir()
	outsideDir := t.TempDir()

	// Create: base/a/ (real directory)
	realA := filepath.Join(base, "a")
	if err := os.Mkdir(realA, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create: base/a/b -> outsideDir (symlink to outside tree)
	symlinkB := filepath.Join(realA, "b")
	if err := os.Symlink(outsideDir, symlinkB); err != nil {
		t.Fatal(err)
	}

	// Ask SafeMkdirAll to create base/a/b/c/d.
	// "b" is a symlink — a secure implementation must reject this.
	target := filepath.Join(base, "a", "b", "c", "d")
	err := SafeMkdirAll(target, WriteOptions{Perm: 0o755})

	if err == nil {
		// Check if directories were created outside the intended tree.
		if _, statErr := os.Stat(filepath.Join(outsideDir, "c", "d")); statErr == nil {
			t.Error("SafeMkdirAll followed a symlink in a middle path component and created directories outside the intended tree")
		} else {
			t.Error("SafeMkdirAll should have rejected the symlink at component 'b'")
		}
	}
}

// ---------------------------------------------------------------------------
// Bug 7: SafeMkdirAll path component is a file (not a directory)
// ---------------------------------------------------------------------------

func TestSafeMkdirAll_FileBlocksDirectory(t *testing.T) {
	base := t.TempDir()

	// Create base/a as a regular file (not a directory).
	filePath := filepath.Join(base, "a")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Ask SafeMkdirAll to create base/a/b — should fail because "a" is a file.
	target := filepath.Join(base, "a", "b")
	err := SafeMkdirAll(target, WriteOptions{Perm: 0o755})
	if err == nil {
		t.Error("SafeMkdirAll should fail when a path component is a regular file")
	}
}

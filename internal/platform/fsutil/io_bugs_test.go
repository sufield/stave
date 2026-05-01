package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Bug 1 (FIXED): LimitedReadAll probe-based overflow detection
// ---------------------------------------------------------------------------

func TestLimitedReadAll_ProbeDetectsOverflow(t *testing.T) {
	// Fixed: LimitedReadAll now reads up to the limit via io.LimitReader
	// (no +1 overshoot), then probes one byte from the original reader.
	// This prevents io.ReadAll from doubling its buffer past the limit.

	origLimit := maxInputFileBytes.Load()
	maxInputFileBytes.Store(1024) // 1KB limit for test
	t.Cleanup(func() { maxInputFileBytes.Store(origLimit) })

	// Input is 2x the limit — rejected via the 1-byte probe.
	oversized := strings.NewReader(strings.Repeat("x", 2048))

	_, err := LimitedReadAll(oversized, "test-stream")
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}
}

func TestLimitedReadAll_ExactlyAtLimit(t *testing.T) {
	origLimit := maxInputFileBytes.Load()
	maxInputFileBytes.Store(1024)
	t.Cleanup(func() { maxInputFileBytes.Store(origLimit) })

	// Input is exactly at the limit — should succeed.
	exact := strings.NewReader(strings.Repeat("x", 1024))

	data, err := LimitedReadAll(exact, "exact-stream")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 1024 {
		t.Fatalf("expected 1024 bytes, got %d", len(data))
	}
}

func TestLimitedReadAll_OneByteOverLimit(t *testing.T) {
	origLimit := maxInputFileBytes.Load()
	maxInputFileBytes.Store(1024)
	t.Cleanup(func() { maxInputFileBytes.Store(origLimit) })

	// Input is 1 byte over the limit — rejected by the probe.
	over := strings.NewReader(strings.Repeat("x", 1025))

	_, err := LimitedReadAll(over, "over-stream")
	if err == nil {
		t.Fatal("expected error for input 1 byte over limit")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}
}

// chainReader yields the contents of `head` first, then delegates
// further Read calls to `tail`. Used to push LimitedReadAll past
// Phase 1 with real bytes and observe Phase 2's probe behavior.
type chainReader struct {
	head []byte
	tail func(p []byte) (int, error)
}

func (c *chainReader) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.tail(p)
}

func TestLimitedReadAll_ProbeErrorPropagated(t *testing.T) {
	origLimit := maxInputFileBytes.Load()
	maxInputFileBytes.Store(1024)
	t.Cleanup(func() { maxInputFileBytes.Store(origLimit) })

	probeErr := errors.New("simulated network failure on probe")
	// First feed exactly 'limit' bytes so Phase 1 succeeds, then have
	// Phase 2's probe see (0, probeErr) instead of (0, io.EOF). The
	// earlier shape silently treated this as "no overflow" and
	// returned the partial data with no error; the fix surfaces the
	// underlying I/O failure.
	r := &chainReader{
		head: []byte(strings.Repeat("x", 1024)),
		tail: func(p []byte) (int, error) { return 0, probeErr },
	}
	_, err := LimitedReadAll(r, "probe-error-stream")
	if err == nil {
		t.Fatal("expected error from probe stage, got nil")
	}
	if !errors.Is(err, probeErr) {
		t.Fatalf("expected probeErr, got %v", err)
	}
}

func TestReadFileOrStdin_UsesLimit(t *testing.T) {
	// Verify that ReadFileOrStdin applies the safety limit to stdin,
	// not raw io.ReadAll (which had no limit at all).
	origLimit := maxInputFileBytes.Load()
	maxInputFileBytes.Store(1024)
	t.Cleanup(func() { maxInputFileBytes.Store(origLimit) })

	oversized := strings.NewReader(strings.Repeat("x", 2048))
	_, err := ReadFileOrStdin("", oversized)
	if err == nil {
		t.Fatal("expected error for oversized stdin")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bug 2 (VERIFIED): SafeMkdirAll detects intermediate symlinks
// ---------------------------------------------------------------------------

func TestSafeMkdirAll_IntermediateSymlinkDetected(t *testing.T) {
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

	// SafeMkdirAll walks component-by-component with Lstat and catches
	// the symlink at "link" before creating "subdir".
	path := filepath.Join(link, "subdir")
	err := SafeMkdirAll(path, WriteOptions{Perm: 0o755})
	if err == nil {
		t.Fatal("SafeMkdirAll should reject intermediate symlink")
	}
	if !errors.Is(err, ErrSymlinkForbidden) {
		t.Errorf("expected ErrSymlinkForbidden, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bug 3 (FIXED): CheckSymlinkSafety accepts deep paths after cap raise
// ---------------------------------------------------------------------------

func TestCheckSymlinkSafety_DeepPathAccepted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("deep path test requires Unix")
	}

	base := t.TempDir()

	// Build a 25-level deep path. With maxPathDepth=512, the walk
	// reaches the existing base dir without hitting the limit.
	parts := make([]string, 25)
	parts[0] = base
	for i := 1; i < len(parts); i++ {
		parts[i] = "d"
	}
	deepPath := filepath.Join(parts...)

	err := CheckSymlinkSafety(deepPath)
	if err != nil {
		t.Errorf("deep path should be accepted with raised cap: %v", err)
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
// Bug 6 (VERIFIED): SafeMkdirAll checks each path component for symlinks
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

	// SafeMkdirAll walks component-by-component with Lstat and catches
	// the symlink at "b" before creating "c/d".
	target := filepath.Join(base, "a", "b", "c", "d")
	err := SafeMkdirAll(target, WriteOptions{Perm: 0o755})
	if err == nil {
		t.Fatal("SafeMkdirAll should reject symlink at middle component 'b'")
	}
	if !errors.Is(err, ErrSymlinkForbidden) {
		t.Errorf("expected ErrSymlinkForbidden, got: %v", err)
	}
	// Verify nothing was created outside the intended tree.
	if _, statErr := os.Stat(filepath.Join(outsideDir, "c")); statErr == nil {
		t.Error("directories should not have been created outside the intended tree")
	}
}

// ---------------------------------------------------------------------------
// Bug 7 (VERIFIED): SafeMkdirAll rejects file blocking directory path
// ---------------------------------------------------------------------------

func TestSafeMkdirAll_FileBlocksDirectory(t *testing.T) {
	base := t.TempDir()

	// Create base/a as a regular file (not a directory).
	filePath := filepath.Join(base, "a")
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// SafeMkdirAll detects that "a" is a file (not a directory) and rejects.
	target := filepath.Join(base, "a", "b")
	err := SafeMkdirAll(target, WriteOptions{Perm: 0o755})
	if err == nil {
		t.Fatal("SafeMkdirAll should fail when a path component is a regular file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %v", err)
	}
}

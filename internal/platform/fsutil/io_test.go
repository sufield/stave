package fsutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCleanUserPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"-", "-"},
		{"a/../b", "b"},
		{"a/./b", "a/b"},
		{"a//b", "a/b"},
		{"./a", "a"},
		{"a/b/", "a/b"},
		{"/absolute/path", "/absolute/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := CleanUserPath(tt.input)
			if got != tt.expected {
				t.Errorf("CleanUserPath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestJoinWithinRoot_Valid(t *testing.T) {
	root := t.TempDir()

	tests := []string{
		"file.yaml",
		"subdir/file.yaml",
		"a/b/c.yaml",
	}

	for _, rel := range tests {
		t.Run(rel, func(t *testing.T) {
			got, err := JoinWithinRoot(root, rel)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.HasPrefix(got, root) {
				t.Errorf("result %q does not start with root %q", got, root)
			}
		})
	}
}

func TestJoinWithinRoot_Traversal(t *testing.T) {
	root := t.TempDir()

	tests := []struct {
		name    string
		relPath string
	}{
		{"parent escape", "../escape.yaml"},
		{"deep escape", "../../../etc/passwd"},
		{"mixed escape", "subdir/../../escape.yaml"},
		{"absolute path", "/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := JoinWithinRoot(root, tt.relPath)
			if err == nil {
				t.Errorf("expected error for relPath %q, got nil", tt.relPath)
			}
			if !filepath.IsAbs(tt.relPath) && !errors.Is(err, ErrPathTraversal) {
				t.Errorf("expected ErrPathTraversal for %q, got: %v", tt.relPath, err)
			}
		})
	}
}

func TestJoinWithinRoot_WindowsTraversal(t *testing.T) {
	if runtime.GOOS != "windows" {
		// On Unix, backslash is valid in filenames but filepath.Clean
		// treats it literally. We still test the traversal logic works.
		root := t.TempDir()
		// This tests that the cleaned path is validated
		_, err := JoinWithinRoot(root, ".."+string(filepath.Separator)+"escape")
		if err == nil {
			t.Error("expected traversal error for platform-specific separator")
		}
	}
}

func TestIsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	tmpDir := t.TempDir()

	// Regular file
	regular := filepath.Join(tmpDir, "regular.txt")
	if err := os.WriteFile(regular, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	isSym, err := IsSymlink(regular)
	if err != nil {
		t.Fatal(err)
	}
	if isSym {
		t.Error("regular file should not be a symlink")
	}

	// Symlink
	link := filepath.Join(tmpDir, "link.txt")
	if err = os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}

	isSym, err = IsSymlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if !isSym {
		t.Error("symlink should be detected")
	}

	// Non-existent path
	isSym, err = IsSymlink(filepath.Join(tmpDir, "nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	if isSym {
		t.Error("non-existent path should not be a symlink")
	}
}

func TestSafeCreateFile_SymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	link := filepath.Join(tmpDir, "link.txt")

	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	// Should refuse without allowSymlink
	_, err := SafeCreateFile(link, WriteOptions{
		Perm:         0o600,
		Overwrite:    true,
		AllowSymlink: false,
	})
	if err == nil {
		t.Fatal("expected symlink refusal")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}

	// Should succeed with allowSymlink
	f, err := SafeCreateFile(link, WriteOptions{
		Perm:         0o600,
		Overwrite:    true,
		AllowSymlink: true,
	})
	if err != nil {
		t.Fatalf("expected success with allowSymlink, got: %v", err)
	}
	f.Close()
}

func TestSafeCreateFile_OverwriteRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	existing := filepath.Join(tmpDir, "existing.txt")

	if err := os.WriteFile(existing, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Should refuse without overwrite
	_, err := SafeCreateFile(existing, WriteOptions{
		Perm:         0o600,
		Overwrite:    false,
		AllowSymlink: true,
	})
	if err == nil {
		t.Fatal("expected overwrite refusal")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}

	// Should succeed with overwrite
	f, err := SafeCreateFile(existing, WriteOptions{
		Perm:         0o600,
		Overwrite:    true,
		AllowSymlink: true,
	})
	if err != nil {
		t.Fatalf("expected success with overwrite, got: %v", err)
	}
	f.Close()
}

func TestSafeWriteFile_OverwriteRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	existing := filepath.Join(tmpDir, "existing.txt")

	if err := os.WriteFile(existing, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := SafeWriteFile(existing, []byte("new"), WriteOptions{
		Perm:         0o600,
		Overwrite:    false,
		AllowSymlink: true,
	})
	if err == nil {
		t.Fatal("expected overwrite refusal")
	}
	if !errors.Is(err, ErrFileExists) {
		t.Errorf("expected ErrFileExists, got: %v", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestSafeWriteFile_SymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	link := filepath.Join(tmpDir, "link.txt")

	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := SafeWriteFile(link, []byte("new"), WriteOptions{
		Perm:         0o600,
		Overwrite:    true,
		AllowSymlink: false,
	})
	if err == nil {
		t.Fatal("expected symlink refusal")
	}
	if !errors.Is(err, ErrSymlinkForbidden) {
		t.Errorf("expected ErrSymlinkForbidden, got: %v", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestSafeMkdirAll_SymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	tmpDir := t.TempDir()
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(tmpDir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	err := SafeMkdirAll(link, WriteOptions{Perm: 0o700})
	if err == nil {
		t.Fatal("expected symlink refusal")
	}
	if !errors.Is(err, ErrSymlinkForbidden) {
		t.Errorf("expected ErrSymlinkForbidden, got: %v", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestValidateBucket_Valid(t *testing.T) {
	valid := []string{
		"my-bucket",
		"my.bucket.name",
		"bucket123",
		"a-b",
		"abc",
	}

	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateBucket(name); err != nil {
				t.Errorf("expected valid bucket name %q, got error: %v", name, err)
			}
		})
	}
}

func TestValidateBucket_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		bucket string
	}{
		{"empty", ""},
		{"forward slash", "bucket/escape"},
		{"backslash", "bucket\\escape"},
		{"traversal", "bucket..name"},
		{"uppercase", "MyBucket"},
		{"too short", "ab"},
		{"starts with dot", ".bucket"},
		{"underscore", "my_bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucket(tt.bucket)
			if err == nil {
				t.Fatalf("expected error for bucket name %q", tt.bucket)
			}
			if !errors.Is(err, ErrInvalidBucket) {
				t.Errorf("expected ErrInvalidBucket, got: %v", err)
			}
		})
	}
}

func TestSafeCreateFile_NewFile(t *testing.T) {
	tmpDir := t.TempDir()
	newFile := filepath.Join(tmpDir, "new.txt")

	f, err := SafeCreateFile(newFile, WriteOptions{
		Perm:         0o600,
		Overwrite:    false,
		AllowSymlink: false,
	})
	if err != nil {
		t.Fatalf("expected success creating new file, got: %v", err)
	}
	f.Close()

	info, err := os.Stat(newFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected permissions 0o600, got %o", perm)
	}
}

func TestReadFileLimited_WithinLimit(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "small.json")
	content := []byte(`{"key":"value"}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFileLimited(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("got %q, want %q", data, content)
	}
}

func TestReadFileLimited_ExceedsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: creates sparse file over 256MB")
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "oversized.json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if truncErr := f.Truncate(maxInputFileBytes + 1); truncErr != nil {
		t.Fatalf("truncate sparse file: %v", truncErr)
	}

	_, err = ReadFileLimited(path)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("expected ErrFileTooLarge, got: %v", err)
	}
	if !strings.Contains(err.Error(), "safety limit") {
		t.Errorf("expected safety limit error, got: %v", err)
	}
}

func TestReadFileLimited_FileNotFound(t *testing.T) {
	_, err := ReadFileLimited("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist error, got: %v", err)
	}
}

func TestLimitedReadAll_WithinLimit(t *testing.T) {
	content := []byte(`{"snapshot":"data"}`)
	r := bytes.NewReader(content)

	data, err := LimitedReadAll(r, "test-source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("got %q, want %q", data, content)
	}
}

func TestLimitedReadAll_ExceedsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: allocates 256MB+")
	}

	// Use an infinite zero reader so we don't pre-allocate 256MB.
	// LimitedReadAll will read maxInputFileBytes+1 bytes via its
	// internal LimitReader, then reject.
	_, err := LimitedReadAll(io.LimitReader(zeroReader{}, maxInputFileBytes+2), "oversized-stdin")
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("expected ErrFileTooLarge, got: %v", err)
	}
	if !strings.Contains(err.Error(), "safety limit") {
		t.Errorf("expected safety limit error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "oversized-stdin") {
		t.Errorf("expected source name in error, got: %v", err)
	}
}

// zeroReader is an infinite reader that produces zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

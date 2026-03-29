package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultWriteOpts(t *testing.T) {
	opts := DefaultWriteOpts()
	if opts.Perm != 0o600 {
		t.Errorf("Perm = %o, want 0600", opts.Perm)
	}
	if opts.Overwrite {
		t.Error("Overwrite should be false")
	}
	if opts.AllowSymlink {
		t.Error("AllowSymlink should be false")
	}
}

func TestConfigWriteOpts(t *testing.T) {
	opts := ConfigWriteOpts()
	if opts.Perm != 0o644 {
		t.Errorf("Perm = %o, want 0644", opts.Perm)
	}
	if !opts.Overwrite {
		t.Error("Overwrite should be true")
	}
	if opts.AllowSymlink {
		t.Error("AllowSymlink should be false")
	}
}

func TestWriteFileAtomic_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	data := []byte("atomic-content")

	if err := WriteFileAtomic(path, data, 0o644); err != nil {
		t.Fatalf("WriteFileAtomic() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("permissions = %o, want 0644", perm)
	}
}

func TestWriteFileAtomic_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "file.txt")

	if err := WriteFileAtomic(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(got) != "test" {
		t.Errorf("content = %q, want test", got)
	}
}

func TestWriteFileAtomic_OverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")

	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
}

func TestWriteFileAtomic_SymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := WriteFileAtomic(link, []byte("new"), 0o600)
	if err == nil {
		t.Fatal("expected symlink refusal for atomic write")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestSafeOpenAppend_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.log")

	f, err := SafeOpenAppend(path, WriteOptions{Perm: 0o644, AllowSymlink: true})
	if err != nil {
		t.Fatalf("SafeOpenAppend() error: %v", err)
	}

	if _, writeErr := f.Write([]byte("line1\n")); writeErr != nil {
		t.Fatalf("Write() error: %v", writeErr)
	}
	f.Close()

	// Append more
	f2, err := SafeOpenAppend(path, WriteOptions{Perm: 0o644, AllowSymlink: true})
	if err != nil {
		t.Fatalf("SafeOpenAppend() second open error: %v", err)
	}
	if _, writeErr := f2.Write([]byte("line2\n")); writeErr != nil {
		t.Fatalf("Write() error: %v", writeErr)
	}
	f2.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "line1\nline2\n" {
		t.Errorf("content = %q, want line1+line2", got)
	}
}

func TestSafeOpenAppend_SymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	link := filepath.Join(dir, "link.log")

	if err := os.WriteFile(target, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := SafeOpenAppend(link, WriteOptions{Perm: 0o644})
	if err == nil {
		t.Fatal("expected symlink refusal")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestCheckSymlinkSafety_RegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSymlinkSafety(path); err != nil {
		t.Fatalf("CheckSymlinkSafety() error for regular file: %v", err)
	}
}

func TestCheckSymlinkSafety_NonExistentWithValidParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.txt")
	if err := CheckSymlinkSafety(path); err != nil {
		t.Fatalf("CheckSymlinkSafety() error for nonexistent file with valid parent: %v", err)
	}
}

func TestCheckSymlinkSafety_SymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	if err := os.WriteFile(target, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := CheckSymlinkSafety(link)
	if err == nil {
		t.Fatal("expected error for symlink target")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestSafeFileSystem_WriteFile(t *testing.T) {
	dir := t.TempDir()
	fs := SafeFileSystem{Overwrite: true, AllowSymlink: true}

	path := filepath.Join(dir, "test.txt")
	if err := fs.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want hello", got)
	}
}

func TestSafeFileSystem_MkdirAll(t *testing.T) {
	dir := t.TempDir()
	fs := SafeFileSystem{AllowSymlink: true}

	path := filepath.Join(dir, "sub", "dir")
	if err := fs.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestFSContentHasher_HashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := FSContentHasher{}
	hash, err := h.HashFile(path)
	if err != nil {
		t.Fatalf("HashFile() error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestFSContentHasher_HashDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":2}`), 0o600); err != nil {
		t.Fatal(err)
	}

	h := FSContentHasher{}
	hash, err := h.HashDir(dir, ".json")
	if err != nil {
		t.Fatalf("HashDir() error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Should be deterministic
	hash2, err := h.HashDir(dir, ".json")
	if err != nil {
		t.Fatal(err)
	}
	if hash != hash2 {
		t.Errorf("non-deterministic: %q != %q", hash, hash2)
	}
}

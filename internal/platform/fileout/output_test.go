package fileout

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenOutputFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "out.json")
	f, err := OpenOutputFile(path, FileOptions{DirPerms: 0o755})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f.Close()
	os.Remove(path)
}

func TestOpenOutputFile_RejectsExistingWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.json")
	os.WriteFile(path, []byte("data"), 0o644)

	_, err := OpenOutputFile(path, FileOptions{Overwrite: false})
	if err == nil {
		t.Fatal("expected error for existing file without overwrite")
	}
}

func TestOpenOutputFile_AllowsOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.json")
	os.WriteFile(path, []byte("data"), 0o644)

	f, err := OpenOutputFile(path, FileOptions{Overwrite: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f.Close()
}

func TestOpenOutputFile_CurrentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	f, err := OpenOutputFile(path, FileOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f.Close()
	os.Remove(path)
}

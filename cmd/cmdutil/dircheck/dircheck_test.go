package dircheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDir_ValidDir(t *testing.T) {
	if err := CheckDir(t.TempDir()); err != nil {
		t.Fatalf("CheckDir(tempdir) error = %v", err)
	}
}

func TestCheckDir_NonExistent(t *testing.T) {
	err := CheckDir("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestCheckDir_IsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, []byte("x"), 0o600)
	err := CheckDir(path)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected 'not a directory' error, got: %v", err)
	}
}

package testutil

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var (
	repoRootOnce sync.Once
	repoRootPath string
)

// RepoRoot returns the stave module root (directory containing go.mod).
// The result is cached across calls.
func RepoRoot(t *testing.T) string {
	t.Helper()
	repoRootOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			t.Fatalf("cannot get working directory: %v", err)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				repoRootPath = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				t.Fatal("cannot find repo root (no go.mod found)")
			}
			dir = parent
		}
	})
	return repoRootPath
}

// TestdataDir returns RepoRoot + "/testdata".
func TestdataDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(RepoRoot(t), "testdata")
}

// E2EDir returns TestdataDir + "/e2e/" + name.
func E2EDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(TestdataDir(t), "e2e", name)
}

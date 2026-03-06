package gitinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}

func setupRepo(t *testing.T) string {
	t.Helper()
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("init\n"), 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "init")
	return repo
}

func TestDetectRepoRootAndHead(t *testing.T) {
	repo := setupRepo(t)
	subdir := filepath.Join(repo, "nested", "dir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	root, ok := DetectRepoRoot(subdir)
	if !ok {
		t.Fatalf("expected repo root")
	}
	rootCanonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval repo root symlinks: %v", err)
	}
	repoCanonical, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("eval temp repo symlinks: %v", err)
	}
	if rootCanonical != repoCanonical {
		t.Fatalf("repo root mismatch: got %q want %q", rootCanonical, repoCanonical)
	}

	head, err := HeadCommit(repo)
	if err != nil {
		t.Fatalf("head commit: %v", err)
	}
	head = strings.TrimSpace(head)
	if len(head) != 40 {
		t.Fatalf("unexpected head length: %q", head)
	}
}

func TestIsDirtyReturnsSortedPaths(t *testing.T) {
	repo := setupRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "z.txt"), []byte("z\n"), 0o644); err != nil {
		t.Fatalf("write z.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}

	dirty, paths, err := IsDirty(repo, []string{"z.txt", "a.txt"})
	if err != nil {
		t.Fatalf("IsDirty: %v", err)
	}
	if !dirty {
		t.Fatalf("expected dirty repo")
	}

	want := []string{"a.txt", "z.txt"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("dirty paths mismatch: got %v want %v", paths, want)
	}
}

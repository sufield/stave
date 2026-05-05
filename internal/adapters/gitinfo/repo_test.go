package gitinfo

import (
	"context"
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

	root, ok := DetectRepoRoot(context.Background(), subdir)
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

	head, err := HeadCommit(context.Background(), repo)
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

	dirty, paths, err := IsDirty(context.Background(), repo, []string{"z.txt", "a.txt"})
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

// TestIsDirtyHandlesRenamedPath pins the porcelain rename parser:
// `git status` emits renames as "R  old -> new" with both source and
// destination on a single line. The earlier shape recorded the
// literal "old -> new" string as a dirty path, so callers checking
// membership against repository paths missed both ends of the
// rename and falsely reported the repo clean. The fix records both
// old and new paths in the dirty set.
func TestIsDirtyHandlesRenamedPath(t *testing.T) {
	repo := setupRepo(t)

	// Seed two committed files so we can rename one of them.
	if err := os.WriteFile(filepath.Join(repo, "old-name.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatalf("write old-name.txt: %v", err)
	}
	runGit(t, repo, "add", "old-name.txt")
	runGit(t, repo, "commit", "-m", "add old-name")

	// Rename via git so the porcelain status reports R rather than
	// a delete + add pair. -k skips dry-run; -f forces overwrite.
	runGit(t, repo, "mv", "old-name.txt", "new-name.txt")

	dirty, paths, err := IsDirty(context.Background(), repo, []string{"old-name.txt", "new-name.txt"})
	if err != nil {
		t.Fatalf("IsDirty: %v", err)
	}
	if !dirty {
		t.Fatalf("expected dirty repo after rename; got clean")
	}
	// Both source and destination of the rename must appear in the
	// dirty set so callers tracking either historic or current
	// path identity see the change.
	want := []string{"new-name.txt", "old-name.txt"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("rename dirty paths mismatch: got %v want %v", paths, want)
	}
}

// Package gitinfo provides git repository inspection utilities for
// detecting repo roots, reading HEAD commits, and checking dirty state.
package gitinfo

import (
	"bufio"
	"bytes"
	"os/exec"
	"slices"
	"strings"
)

func hasGit() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// DetectRepoRoot returns the git repository root containing dir, or false if dir is not inside a git working tree.
func DetectRepoRoot(dir string) (string, bool) {
	if !hasGit() {
		return "", false
	}
	// #nosec G204 -- exec.Command does not invoke a shell; "-C dir" is passed as a literal argument.
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", false
	}
	return root, true
}

// HeadCommit returns the commit hash of HEAD in the repository at repoRoot.
func HeadCommit(repoRoot string) (string, error) {
	if !hasGit() {
		return "", nil
	}
	// #nosec G204 -- exec.Command does not invoke a shell; repoRoot is a literal git argument.
	cmd := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsDirty reports whether any of the given paths have uncommitted changes in the repository at repoRoot.
func IsDirty(repoRoot string, paths []string) (bool, []string, error) {
	if !hasGit() {
		return false, nil, nil
	}
	args := []string{"-C", repoRoot, "status", "--porcelain", "--"}
	args = append(args, paths...)
	// #nosec G204 -- exec.Command does not invoke a shell; args are passed directly to git.
	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		return false, nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return false, nil, nil
	}
	dirty := map[string]bool{}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := s.Text()
		if len(line) < 4 {
			continue
		}
		p := strings.TrimSpace(line[3:])
		if p == "" {
			continue
		}
		dirty[p] = true
	}
	list := make([]string, 0, len(dirty))
	for p := range dirty {
		list = append(list, p)
	}
	slices.Sort(list)
	return len(list) > 0, list, nil
}

// InitRepo initializes a new git repository in dir.
func InitRepo(dir string) error {
	if !hasGit() {
		return exec.ErrNotFound
	}
	// #nosec G204 -- exec.Command does not invoke a shell; "-C dir" is passed as a literal argument.
	cmd := exec.Command("git", "-C", dir, "init")
	_, err := cmd.Output()
	return err
}

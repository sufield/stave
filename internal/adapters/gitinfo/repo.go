// Package gitinfo provides git repository inspection utilities for
// detecting repo roots, reading HEAD commits, and checking dirty state.
package gitinfo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

func hasGit() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// DetectRepoRoot returns the git repository root containing dir, or false if dir is not inside a git working tree.
func DetectRepoRoot(ctx context.Context, dir string) (string, bool) {
	if !hasGit() {
		return "", false
	}
	// #nosec G204 -- exec.Command does not invoke a shell; "-C dir" is passed as a literal argument.
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel")
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
func HeadCommit(ctx context.Context, repoRoot string) (string, error) {
	if !hasGit() {
		return "", nil
	}
	// #nosec G204 -- exec.Command does not invoke a shell; repoRoot is a literal git argument.
	cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsDirty reports whether any of the given paths have uncommitted changes in the repository at repoRoot.
func IsDirty(ctx context.Context, repoRoot string, paths []string) (bool, []string, error) {
	if !hasGit() {
		return false, nil, nil
	}
	// Reject paths containing newlines, null bytes, or other
	// control characters before invoking git. The `--` separator
	// already prevents flag-injection at the argv level, but a
	// path with embedded \n could still confuse downstream
	// scanner-based parsers (the porcelain output below is
	// line-oriented). NUL is reserved as the field separator for
	// machine-readable git output and must never appear in a path.
	if err := validateGitPaths(paths); err != nil {
		return false, nil, err
	}
	args := []string{"-C", repoRoot, "status", "--porcelain", "--"}
	args = append(args, paths...)
	// #nosec G204 -- exec.Command does not invoke a shell; args are passed directly to git.
	cmd := exec.CommandContext(ctx, "git", args...)
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
		// Porcelain status format: "XY <path>" where XY is the
		// staged/unstaged status pair. Renames are reported with
		// X='R' and the path field rendered as "<old> -> <new>".
		// Treating that whole string as a single dirty path was
		// wrong: callers checking membership against repo paths
		// looked for "<old> -> <new>" verbatim and missed both
		// the source and destination of the rename. Split on the
		// canonical " -> " separator and record the destination
		// (the path that exists post-rename); also record the
		// source so callers tracking historic-path identity see
		// the rename through.
		statusPair := line[:2]
		p := strings.TrimSpace(line[3:])
		if p == "" {
			continue
		}
		isRename := statusPair[0] == 'R' || statusPair[1] == 'R'
		if isRename {
			if oldPath, newPath, ok := strings.Cut(p, " -> "); ok {
				dirty[strings.TrimSpace(oldPath)] = true
				dirty[strings.TrimSpace(newPath)] = true
				continue
			}
		}
		dirty[p] = true
	}
	// Surface scanner errors (e.g. token too long for the default
	// buffer) instead of silently returning the partial dirty set.
	// A truncated scan would tell the caller "clean" for paths that
	// happened to fall after the truncation point.
	if err := s.Err(); err != nil {
		return false, nil, fmt.Errorf("scan git status: %w", err)
	}
	list := make([]string, 0, len(dirty))
	for p := range dirty {
		list = append(list, p)
	}
	slices.Sort(list)
	return len(list) > 0, list, nil
}

// validateGitPaths rejects paths that contain newlines, null bytes,
// or other ASCII control characters. The git porcelain output below
// is line-oriented; an embedded \n in a path argument would let a
// hostile callsite split a single fake "modified" line into two
// records (one observed, one synthesized) and corrupt the dirty
// set returned to the caller. NUL is reserved as the field separator
// for machine-readable git output and must never appear in a path.
func validateGitPaths(paths []string) error {
	for _, p := range paths {
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c == 0 || c == '\n' || c == '\r' || (c < 0x20 && c != '\t') {
				return fmt.Errorf("path %q contains control character at offset %d", p, i)
			}
		}
	}
	return nil
}

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// SafeDir resolves path to an absolute path and verifies it is
// contained within base. Returns the resolved absolute path or
// an error if the path escapes base.
//
// Containment is checked twice: first lexically (Abs+Rel, a cheap
// reject for obvious ../ traversal) and then after resolving symlinks
// on both sides via evalWithinRoot. The symlink pass is what closes
// the escape where a path lexically inside base is (or descends
// through) a symlink whose target lives outside base — a lexical-only
// check accepts it, then reads/writes land outside the sandbox.
func SafeDir(path, base string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving path %q: %w", path, err)
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolving base %q: %w", base, err)
	}
	rel, err := filepath.Rel(absBase, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path %q (resolved: %q) is outside base directory %q", path, abs, absBase)
	}
	if err := evalWithinRoot(absBase, abs); err != nil {
		return "", fmt.Errorf("path %q is outside base directory %q: %w", path, absBase, err)
	}
	return abs, nil
}

// evalWithinRoot verifies that target, after resolving every symlink in
// its existing portion, remains lexically contained within root (also
// symlink-resolved). It is the symlink-aware companion to the lexical
// Abs+Rel containment check: lexical checks operate on path strings and
// cannot see that an in-root component is a symlink pointing elsewhere.
//
// Neither root nor target need fully exist — the deepest existing
// ancestor is resolved and any not-yet-existing suffix re-appended, so
// a symlinked ancestor cannot smuggle the path out of root while a
// genuinely new leaf (a file about to be created) is still accepted.
func evalWithinRoot(root, target string) error {
	resolvedRoot, err := resolveExisting(root)
	if err != nil {
		return fmt.Errorf("resolve root %q: %w", root, err)
	}
	resolvedTarget, err := resolveExisting(target)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", target, err)
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: resolved target %q escapes resolved root %q", ErrPathTraversal, resolvedTarget, resolvedRoot)
	}
	return nil
}

// resolveExisting resolves symlinks on the deepest existing prefix of p
// and re-appends the trailing components that do not exist yet. A path
// that exists in full is returned fully resolved; a path whose leaf is
// absent has its parent resolved (the absent leaf cannot itself be a
// symlink, so re-appending it is safe).
func resolveExisting(p string) (string, error) {
	p = filepath.Clean(p)
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("eval symlinks %q: %w", p, err)
	}
	parent := filepath.Dir(p)
	if parent == p {
		// Reached the filesystem root without finding an existing
		// component; nothing to resolve.
		return p, nil
	}
	resolvedParent, err := resolveExisting(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(p)), nil
}

// SafeFilename returns an error if name is not safe to use as a
// filename component. Rejects path separators, null bytes, and
// empty strings.
func SafeFilename(name string) error {
	if name == "" {
		return errors.New("filename must not be empty")
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("filename %q contains illegal characters", name)
	}
	return nil
}

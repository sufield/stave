package fsutil

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// SafeDir resolves path to an absolute path and verifies it is
// contained within base. Returns the resolved absolute path or
// an error if the path escapes base.
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
	return abs, nil
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

package ui

import (
	"os"
	"path/filepath"
)

// RelativeDisplayPath returns a concise path for terminal output.
// If the path can be expressed relative to the current working directory,
// it returns the relative form. Otherwise it returns the path as-is.
// Use "." for the current directory rather than an empty string.
func RelativeDisplayPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return path
	}
	if rel == "" {
		return "."
	}
	return rel
}

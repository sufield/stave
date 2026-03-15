package yaml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	registryFilename = "controls.index.json"
	registryDir      = "_registry"
)

// registryIndex represents the _registry/controls.index.json file format.
type registryIndex struct {
	SchemaVersion string   `json:"schema_version"`
	Files         []string `json:"files"`
}

// resolveControlPaths identifies control YAML files. It prioritizes a manifest
// file if present in the _registry folder, falling back to a recursive scan.
//
// If the registry exists but is malformed, an error is returned immediately
// rather than silently falling back to a walk (which could produce inconsistent
// results in CI/CD).
func resolveControlPaths(ctx context.Context, dir string) ([]string, error) {
	indexPath := filepath.Join(dir, registryDir, registryFilename)

	paths, err := loadPathsFromRegistry(ctx, dir, indexPath)
	if err == nil {
		return paths, nil
	}

	// If the registry simply doesn't exist, fall back to a manual scan.
	// Any other error (permissions, malformed JSON) should stop execution.
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("registry error: %w", err)
	}

	return scanForControlFiles(ctx, dir)
}

// loadPathsFromRegistry attempts to read and parse the controls.index.json file.
func loadPathsFromRegistry(ctx context.Context, root, indexPath string) ([]string, error) {
	data, err := fsutil.ReadFileLimited(indexPath)
	if err != nil {
		return nil, err
	}

	var idx registryIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("malformed registry JSON at %q: %w", indexPath, err)
	}

	paths := make([]string, 0, len(idx.Files))
	for _, relPath := range idx.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		absPath, err := fsutil.JoinWithinRoot(root, relPath)
		if err != nil {
			return nil, fmt.Errorf("invalid registry entry %q: %w", relPath, err)
		}
		paths = append(paths, absPath)
	}

	return paths, nil
}

// scanForControlFiles manually crawls the directory tree to find YAML files.
func scanForControlFiles(ctx context.Context, root string) ([]string, error) {
	var paths []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			// Skip _ and . prefixed directories (e.g. _registry, .git)
			// but not the root directory itself.
			if path != root && (strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}

		if isControlFile(path) {
			paths = append(paths, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("scanning for controls in %q: %w", root, err)
	}

	return paths, nil
}

// isControlFile returns true if the file is a YAML control and not a template
// example or hidden file.
func isControlFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	name := filepath.Base(path)
	if strings.Contains(name, ".example.") {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	return true
}

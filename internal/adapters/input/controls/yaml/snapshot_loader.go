package yaml

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// registryIndex represents the _registry/controls.index.json file format.
type registryIndex struct {
	SchemaVersion string   `json:"schema_version"`
	Files         []string `json:"files"`
}

// resolveControlPaths resolves control file paths via registry fast-path or recursive walk fallback.
func resolveControlPaths(ctx context.Context, dir string) ([]string, error) {
	indexPath := filepath.Join(dir, "_registry", "controls.index.json")
	if paths, handled, err := resolvePathsFromRegistryIndex(ctx, dir, indexPath); handled {
		return paths, err
	}
	return walkControlPaths(ctx, dir)
}

func resolvePathsFromRegistryIndex(ctx context.Context, dir, indexPath string) ([]string, bool, error) {
	data, err := fsutil.ReadFileLimited(indexPath)
	if err == nil {
		paths, parseErr := parseRegistryIndexPaths(ctx, dir, indexPath, data)
		return paths, true, parseErr
	}
	if !os.IsNotExist(err) {
		return nil, true, fmt.Errorf("read registry index: %w", err)
	}
	return nil, false, nil
}

func parseRegistryIndexPaths(ctx context.Context, dir, indexPath string, data []byte) ([]string, error) {
	var idx registryIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse registry index %s: %w", indexPath, err)
	}
	paths := make([]string, 0, len(idx.Files))
	for _, relPath := range idx.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		absPath, err := fsutil.JoinWithinRoot(dir, relPath)
		if err != nil {
			return nil, fmt.Errorf("invalid registry entry %q: %w", relPath, err)
		}
		paths = append(paths, absPath)
	}
	return paths, nil
}

func walkControlPaths(ctx context.Context, dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// Skip _-prefixed directories (e.g., _registry/).
		if d.IsDir() && d.Name() != filepath.Base(dir) && strings.HasPrefix(d.Name(), "_") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		if !isYAML(path) {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func isYAML(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yaml" || ext == ".yml"
}

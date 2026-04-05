package pack

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// ValidateStrict performs deep integrity checks on the registry.
// It verifies all referenced control files exist and that no embedded YAML
// files are orphaned (present on disk but missing from index metadata).
func (r *PackIndex) ValidateStrict(fsys embed.FS) error {
	for id, ref := range r.controls {
		refPath := normalizeControlFSPath(ref.Path)
		if refPath == "" {
			return fmt.Errorf("strict validation failed: control %s has empty path", id)
		}
		if _, err := fs.Stat(fsys, refPath); err != nil {
			return fmt.Errorf("strict validation failed: control %s references missing file %q", id, ref.Path)
		}
	}

	orphans, err := r.VerifyNoOrphans(fsys, "embedded")
	if err != nil {
		return fmt.Errorf("strict validation failed: %w", err)
	}
	if len(orphans) > 0 {
		return fmt.Errorf("strict validation failed: found %d orphaned files not in index.yaml", len(orphans))
	}
	return nil
}

func normalizeControlFSPath(p string) string {
	clean := path.Clean(strings.TrimSpace(p))
	if clean == "." || clean == "" {
		return ""
	}
	if strings.HasPrefix(clean, "embedded/") {
		return clean
	}
	if idx := strings.Index(clean, "/embedded/"); idx >= 0 {
		return clean[idx+1:]
	}
	return clean
}

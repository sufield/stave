package template

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadAll resolves templates from all layers in priority order.
// First match wins for name collisions: explicit dir > project-local >
// user dir > embedded.
func LoadAll(explicitDir string, embeddedFS fs.FS) ([]Template, error) {
	seen := make(map[string]bool)
	var all []Template

	dirs := []string{}
	if explicitDir != "" {
		dirs = append(dirs, explicitDir)
	}
	dirs = append(dirs, "./stave-templates")
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".stave", "templates"))
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		ts, err := LoadFromFS(os.DirFS(dir), ".")
		if err != nil {
			return nil, fmt.Errorf("load templates from %s: %w", dir, err)
		}
		all = mergeTemplates(all, ts, seen)
	}

	embedded, err := LoadFromFS(embeddedFS, ".")
	if err != nil {
		return nil, fmt.Errorf("load embedded templates: %w", err)
	}
	all = mergeTemplates(all, embedded, seen)

	return all, nil
}

func mergeTemplates(dst, src []Template, seen map[string]bool) []Template {
	for i := range src {
		if !seen[src[i].Metadata.Name] {
			seen[src[i].Metadata.Name] = true
			dst = append(dst, src[i])
		}
	}
	return dst
}

package templatefs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	tmpl "github.com/sufield/stave/pkg/stave/template"
)

// LoadAll resolves templates from all layers in priority order.
// First match wins for name collisions: explicit dir > project-local >
// user dir > embedded.
func LoadAll(explicitDir string, embeddedFS fs.FS) ([]tmpl.Template, error) {
	seen := make(map[string]bool)
	var all []tmpl.Template

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
		ts, err := tmpl.LoadFromFS(os.DirFS(dir), ".")
		if err != nil {
			return nil, fmt.Errorf("load templates from %s: %w", dir, err)
		}
		for i := range ts {
			if !seen[ts[i].Metadata.Name] {
				seen[ts[i].Metadata.Name] = true
				all = append(all, ts[i])
			}
		}
	}

	// Embedded templates last (lowest priority)
	embedded, err := tmpl.LoadFromFS(embeddedFS, ".")
	if err != nil {
		return nil, fmt.Errorf("load embedded templates: %w", err)
	}
	for i := range embedded {
		if !seen[embedded[i].Metadata.Name] {
			seen[embedded[i].Metadata.Name] = true
			all = append(all, embedded[i])
		}
	}

	return all, nil
}

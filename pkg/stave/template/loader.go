package template

import (
	"fmt"
	"io/fs"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadFromFS discovers and loads all templates from a filesystem.
// Each template lives in its own subdirectory containing a template.yaml.
func LoadFromFS(fsys fs.FS, root string) ([]Template, error) {
	var templates []Template

	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("read template directory %q: %w", root, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(root, entry.Name(), "template.yaml")
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			continue // skip directories without template.yaml
		}

		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		templates = append(templates, t)
	}

	return templates, nil
}

package pack

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"gopkg.in/yaml.v3"
)

// controlHeader contains only the fields needed to derive ControlRef from a
// control YAML file. This avoids importing the full control definition type
// and keeps the derivation self-contained within the pack package.
type controlHeader struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// DeriveControlRefs walks the embedded filesystem under root and builds a
// ControlRef map by reading the id and name fields from each control YAML.
// The path is derived from the filesystem walk path. This produces the same
// data that was previously hand-maintained in the controls: section of
// index.yaml.
func DeriveControlRefs(fsys embed.FS, root string) (map[kernel.ControlID]ControlRef, error) {
	refs := make(map[kernel.ControlID]ControlRef)

	err := walkControlYAMLs(fsys, root, func(p string, _ fs.DirEntry) error {
		// Skip non-control files (index.yaml, README, etc.)
		if !strings.HasPrefix(path.Base(p), "CTL.") {
			return nil
		}

		data, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", p, readErr)
		}

		var hdr controlHeader
		if yamlErr := yaml.Unmarshal(data, &hdr); yamlErr != nil {
			return fmt.Errorf("parse %s: %w", p, yamlErr)
		}
		if hdr.ID == "" {
			return fmt.Errorf("control at %s has empty id field", p)
		}

		// Reject duplicate control IDs: two YAML files claiming the
		// same id silently let the second registration win in the
		// previous shape, which produced a "phantom" definition for
		// whichever file the embed walk visited last. Fail loudly
		// with both paths so the author can see the collision.
		key := kernel.ControlID(hdr.ID)
		if existing, dup := refs[key]; dup {
			return fmt.Errorf("duplicate control ID %q: defined in %s and %s", hdr.ID, existing.Path, p)
		}
		refs[key] = ControlRef{
			Path:    p,
			Summary: hdr.Name,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("derive control refs: %w", err)
	}
	return refs, nil
}

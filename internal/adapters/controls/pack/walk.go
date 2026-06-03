package pack

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// walkControlYAMLs invokes visitor for every .yaml file under root in fsys,
// applying the project's standard skip rules:
//
//   - directories whose names start with `_` or `.` (e.g. `_triage/`,
//     `.cache/`) are skipped at any depth except root
//   - non-yaml files are skipped silently
//
// The visitor receives the cleaned file path; it can return fs.SkipDir or
// any error to abort the walk. The helper exists so derive.go and
// VerifyNoOrphans share one walk skeleton — the prior shape duplicated
// the same skip logic and a divergence between the two would silently
// drop files from one walker but not the other.
func walkControlYAMLs(fsys fs.FS, root string, visitor func(p string, d fs.DirEntry) error) error {
	root = path.Clean(strings.TrimSpace(root))
	if err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		return visitor(path.Clean(p), d)
	}); err != nil {
		return fmt.Errorf("walk control YAMLs in %s: %w", root, err)
	}
	return nil
}

package app

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestHexagonalDependencyDirection enforces inward dependency flow:
//   - domain must not import adapters/app/cmd layers
//   - app must not import adapters/cmd layers
func TestHexagonalDependencyDirection(t *testing.T) {
	root := findModuleRoot(t)

	type rule struct {
		dirPrefix string
		forbidden []string
		allowed   []string // exceptions within forbidden prefixes
	}

	rules := []rule{
		{
			dirPrefix: filepath.Join("pkg", "alpha", "domain"),
			forbidden: []string{
				"github.com/sufield/stave/internal/adapters/",
				"github.com/sufield/stave/internal/app",
				"github.com/sufield/stave/cmd/",
			},
		},
		{
			dirPrefix: filepath.Join("internal", "app"),
			forbidden: []string{
				"github.com/sufield/stave/internal/adapters/",
				"github.com/sufield/stave/internal/platform/",
				"github.com/sufield/stave/internal/doctor",
				"github.com/sufield/stave/cmd/",
				"os/exec",
			},
		},
		{
			dirPrefix: filepath.Join("internal", "adapters"),
			forbidden: []string{
				"github.com/sufield/stave/internal/app/",
				"github.com/sufield/stave/cmd/",
			},
			allowed: []string{
				"github.com/sufield/stave/internal/app/contracts",
			},
		},
	}

	fset := token.NewFileSet()
	var violations []string

	for _, r := range rules {
		absDir := filepath.Join(root, r.dirPrefix)
		err := filepath.WalkDir(absDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}

			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, "\"")
				for _, ban := range r.forbidden {
					if p == ban || strings.HasPrefix(p, ban) {
						isAllowed := false
						for _, allow := range r.allowed {
							if p == allow || strings.HasPrefix(p, allow) {
								isAllowed = true
								break
							}
						}
						if !isAllowed {
							violations = append(violations, rel+": imports "+p)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", absDir, err)
		}
	}

	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("hexagonal dependency violation: %s", v)
	}
}

func findModuleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find module root (go.mod not found)")
		}
		dir = parent
	}
}

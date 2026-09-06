package lint

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestArchitecture_FacadeOnly enforces the Phase-3 facade bar for the
// `stave lint` command: production code here may import only pkg/stave,
// cmd/cmdutil, stdlib, third-party CLI deps, and the four exempt CLI helpers.
// _test.go files are exempt.
//
// The load -> compute -> render pipeline moved into
// pkg/stave/internal/validatecmd (surfaced as stave.ValidateProject /
// stave.ValidateContent). The command keeps flag wiring, project-context
// resolution, stdin reading, the --kind alias normalization, and injects the
// cli/ui-bound severity-label / template callbacks. See
// docs/architecture/pkg-stave-facade.md.
func TestArchitecture_FacadeOnly(t *testing.T) {
	exempt := []string{
		`"github.com/sufield/stave/internal/cli/ui"`,
		`"github.com/sufield/stave/internal/platform/fsutil"`,
		`"github.com/sufield/stave/internal/platform/metadata"`,
		`"github.com/sufield/stave/internal/util/jsonutil"`,
	}
	const internalPrefix = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	var offenders []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(".", e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			if !strings.HasPrefix(imp.Path.Value, internalPrefix) {
				continue
			}
			if slices.Contains(exempt, imp.Path.Value) {
				continue
			}
			offenders = append(offenders, path+": "+imp.Path.Value)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("cmd/apply/lint/ production code may import only pkg/stave, cmd/cmdutil, stdlib, and the\n"+
			"four exempt CLI helpers (see docs/architecture/pkg-stave-facade.md).\n"+
			"Forbidden internal imports:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

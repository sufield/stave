package generate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestArchitecture_FacadeOnly enforces the Phase-3 facade bar for
// `stave ci enforce`: production code here may import only pkg/stave,
// cmd/cmdutil, stdlib, third-party CLI deps, and the four exempt CLI
// helpers. _test.go files are exempt.
//
// Evaluation loading, target extraction, template rendering, and the
// symlink-safe file write moved into stave.GenerateEnforcement
// (pkg/stave/enforce_generate.go); the command keeps only flag wiring and
// mode parsing (ParseMode reports invalid input via ui.EnumError, which
// pkg/stave cannot import). See docs/architecture/pkg-stave-facade.md.
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
		t.Errorf("cmd/enforce/generate/ production code may import only pkg/stave, cmd/cmdutil, stdlib, and the four\n"+
			"exempt CLI helpers (see docs/architecture/pkg-stave-facade.md).\n"+
			"Forbidden internal imports:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

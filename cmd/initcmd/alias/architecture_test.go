package alias

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
// `stave init alias`: every Go file here may import only pkg/stave,
// cmd/cmdutil, the standard library, third-party CLI deps, and the four
// CLI-shaped shared helpers that are an explicit facade exemption. Any
// other internal/ import is domain/orchestration leakage.
//
// This command's only non-exempt internal import was the OutputFormat
// type from internal/app/contracts; it now uses cmdutil.OutputFormat
// (a type alias re-exported from cmd/cmdutil — a CLI-presentation
// concern). See docs/architecture/pkg-stave-facade.md.
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
		t.Errorf("cmd/initcmd/alias/ may import only pkg/stave, cmd/cmdutil, stdlib, and the four exempt\n"+
			"CLI helpers (see docs/architecture/pkg-stave-facade.md). Move new capability into pkg/stave\n"+
			"or use a cmd/cmdutil re-export.\nForbidden internal imports:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

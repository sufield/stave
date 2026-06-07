package compliance

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
// `stave inspect compliance`: every Go file here may import only
// pkg/stave, cmd/cmdutil, the standard library, third-party CLI deps
// (cobra), and the four CLI-shaped *shared* helpers that are an explicit
// facade exemption. Any OTHER internal/ import is domain/orchestration
// leakage — move the capability into pkg/stave and consume it here.
//
// The crosswalk orchestration moved into stave.ResolveCrosswalk
// (pkg/stave/crosswalk.go) in this Phase-3 migration. The exemption
// (the four helpers below) exists because they are shared with internal/
// and cannot move to cmd/ without inverting the dependency direction —
// see docs/architecture/pkg-stave-facade.md.
func TestArchitecture_FacadeOnly(t *testing.T) {
	// The CLI-shaped shared helpers cmd/ may import (the documented
	// facade exemption). Everything else under internal/ is leakage.
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
		t.Errorf("cmd/inspect/compliance/ may import only pkg/stave, cmd/cmdutil, stdlib, and the four\n"+
			"exempt CLI helpers (see docs/architecture/pkg-stave-facade.md). Move new capability into\n"+
			"pkg/stave and consume it through the facade.\nForbidden internal imports:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

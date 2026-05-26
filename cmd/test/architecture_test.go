package test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchitecture_NoInternalImports enforces the facade rule for
// `stave test`: every Go file in this directory must depend only
// on pkg/stave, cobra, and the standard library. The orchestration
// (load controls, build CEL evaluator, run cases) lives in
// [stave.RunControlTests]; the command is now flag binding + one
// library call + format dispatch.
//
// This is the sixth command to clear the facade bar after
// cmd/stave-mcp/, cmd/gaps/, cmd/readiness/, cmd/score/, and
// cmd/exportinvariants/. Migration tracker + plan:
// docs/architecture/pkg-stave-facade.md.
func TestArchitecture_NoInternalImports(t *testing.T) {
	const forbidden = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/test dir: %v", err)
	}

	var offenders []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(".", e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			if strings.HasPrefix(imp.Path.Value, forbidden) {
				offenders = append(offenders, path+": "+imp.Path.Value)
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("cmd/test/ must import only pkg/stave, cobra, and stdlib (see docs/architecture/pkg-stave-facade.md).\n"+
			"Move new capability into pkg/stave and consume it through the facade.\n"+
			"Forbidden imports found:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

package score

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchitecture_NoInternalImports enforces the facade rule for
// `stave score`: every Go file in this directory must depend only
// on pkg/stave, cobra, and the standard library. The orchestration
// (load assessments, parse weights, build chain budget, sort by
// time, compute, render) moved into pkg/stave; this command is now
// flag binding + library calls + format dispatch.
//
// This is the fourth command to clear the facade bar, after
// cmd/stave-mcp/, cmd/gaps/, and cmd/readiness/. The migration
// plan in docs/architecture/pkg-stave-facade.md tracks the rest;
// the existing `cmd-no-infra` depguard rule in .golangci.yml plus
// per-command architecture tests are how the rule ratchets up
// command by command without one big-bang rewrite.
func TestArchitecture_NoInternalImports(t *testing.T) {
	const forbidden = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/score dir: %v", err)
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
		t.Errorf("cmd/score/ must import only pkg/stave, cobra, and stdlib (see docs/architecture/pkg-stave-facade.md).\n"+
			"Move new capability into pkg/stave and consume it through the facade.\n"+
			"Forbidden imports found:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchitecture_NoInternalImports enforces the facade rule for the
// MCP server: every Go file in cmd/stave-mcp/ must depend only on
// pkg/stave (and the standard library). This holds today by design —
// the server consumes pkg/stave directly so new capability lands once,
// in the library, and is shared with the CLI. The test prevents a
// future "just one quick internal import" from eroding that boundary.
//
// The CLI proper (cmd/, excluding cmd/stave-mcp/) is NOT yet at this
// bar — see docs/architecture/pkg-stave-facade.md for the migration
// plan. This test is the foothold the rest follows.
func TestArchitecture_NoInternalImports(t *testing.T) {
	const forbidden = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/stave-mcp dir: %v", err)
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
		t.Errorf("cmd/stave-mcp/ must import only pkg/stave + stdlib (see docs/architecture/pkg-stave-facade.md).\n"+
			"Move the capability into pkg/stave and consume it through the facade.\n"+
			"Forbidden imports found:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

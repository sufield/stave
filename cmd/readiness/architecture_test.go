package readiness

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchitecture_NoInternalImports enforces the facade rule for
// `stave readiness`: every Go file in this directory must depend
// only on pkg/stave (and the standard library). The orchestration
// moved into [stave.Readiness] in pkg/stave/readiness.go; the
// command is now flag binding + one library call + output
// formatting.
//
// Third command to clear the facade bar (after cmd/stave-mcp and
// cmd/gaps). The migration plan in
// docs/architecture/pkg-stave-facade.md tracks the rest; the
// `readiness-facade-only` depguard rule in .golangci.yml plus this
// per-command architecture test are how the rule ratchets up
// command by command without one big-bang rewrite.
func TestArchitecture_NoInternalImports(t *testing.T) {
	const forbidden = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/readiness dir: %v", err)
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
		t.Errorf("cmd/readiness/ must import only pkg/stave + stdlib (see docs/architecture/pkg-stave-facade.md).\n"+
			"Move new capability into pkg/stave and consume it through the facade.\n"+
			"Forbidden imports found:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

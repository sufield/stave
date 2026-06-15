package gaps

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestArchitecture_NoInternalImports enforces the facade rule for
// `stave gaps`: every Go file in this directory must depend only on
// pkg/stave, cmd/cmdutil (CLI infrastructure shared across commands),
// and the standard library. The orchestration moved into [stave.Gaps]
// in pkg/stave/gaps.go; the command is now flag binding + one library
// call + output formatting.
//
// This is the second command to clear the facade bar after
// cmd/mcp/architecture_test.go. The migration plan in
// docs/architecture/pkg-stave-facade.md tracks the rest; the existing
// `cmd-no-infra` depguard rule in .golangci.yml plus per-command
// architecture tests are how the rule ratchets up command by command
// without one big-bang rewrite.
func TestArchitecture_NoInternalImports(t *testing.T) {
	const forbidden = `"github.com/sufield/stave/internal/`

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd/gaps dir: %v", err)
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
		t.Errorf("cmd/gaps/ must import only pkg/stave, cmd/cmdutil, and stdlib (see docs/architecture/pkg-stave-facade.md).\n"+
			"Move new capability into pkg/stave and consume it through the facade.\n"+
			"Forbidden imports found:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

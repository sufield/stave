package enginetest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDomainLayerBoundary ensures that engine packages never import from
// adapters, platform, CLI, or application layers. This is the structural
// guardrail that keeps the core evaluation engine decoupled from I/O
// and framework concerns.
func TestDomainLayerBoundary(t *testing.T) {
	forbidden := []string{
		"/internal/adapters/",
		"/internal/platform/",
		"/internal/cli/",
		"/internal/app/",
		"/internal/pruner/",
		"/internal/sanitize/",
		"/internal/trace/",
		"/internal/config",
		"/internal/builtin/",
		"/internal/compliance/",
		"/internal/doctor/",
		"/internal/safetyenvelope/",
		"/cmd/",
	}

	// Engine packages moved from pkg/alpha/domain/ to internal/core/.
	engineDirs := []string{
		"kernel", "asset", "evaluation", "controldef", "predicate",
		"ports", "maps", "retention", "snapplan", "schemaval",
		"diag", "s3", "securityaudit",
	}

	fset := token.NewFileSet()
	checked := 0

	for _, dir := range engineDirs {
		dirPath := filepath.Join("..", dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue
		}
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				t.Errorf("parse %s: %v", path, parseErr)
				return nil
			}

			for _, imp := range f.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				for _, pattern := range forbidden {
					if strings.Contains(importPath, pattern) {
						t.Errorf("%s imports forbidden package %s (contains %q)\n"+
							"Engine packages must not depend on adapters, platform, CLI, or application code.",
							path, importPath, pattern)
					}
				}
			}
			checked++
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if checked == 0 {
		t.Fatal("no engine source files found — test may be running from wrong directory")
	}
	t.Logf("checked %d engine source files for boundary violations", checked)
}

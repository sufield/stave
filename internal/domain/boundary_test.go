package domain_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDomainLayerBoundary ensures that domain packages never import from
// adapters, platform, CLI, or application layers. This is the structural
// guardrail that keeps the core evaluation engine decoupled from I/O
// and framework concerns.
func TestDomainLayerBoundary(t *testing.T) {
	// Forbidden import path fragments — domain must not depend on these.
	forbidden := []string{
		"/internal/adapters/",
		"/internal/platform/",
		"/internal/cli/",
		"/internal/app/",
		"/internal/pruner/",
		"/internal/sanitize/",
		"/internal/trace/",
		"/internal/config",
		"/internal/configservice/",
		"/internal/builtin/",
		"/internal/compliance/",
		"/internal/doctor/",
		"/internal/safetyenvelope/",
		"/cmd/",
	}

	fset := token.NewFileSet()
	checked := 0

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
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
						"The domain layer must not depend on adapters, platform, CLI, or application code.",
						path, importPath, pattern)
				}
			}
		}
		checked++
		return nil
	})

	if err != nil {
		t.Fatalf("walk domain directory: %v", err)
	}
	if checked == 0 {
		t.Fatal("no domain source files found — test may be running from wrong directory")
	}
	t.Logf("checked %d domain source files for boundary violations", checked)
}

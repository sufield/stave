package apply

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestApplyCommandsDoNotImportExtractors ensures that evaluation commands
// do not import extractor packages, maintaining the contract boundary.
//
// This is a guardrail to prevent regressions where evaluation becomes
// coupled to specific extractors.
func TestApplyCommandsDoNotImportExtractors(t *testing.T) {
	// Get the directory of this test file
	cmdDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	// Command package files that should NOT import extractor packages.
	applyFiles := []string{
		"command.go",
		"handler.go",
		"options.go",
		"profile.go",
		"deps.go",
		"output.go",
		"support.go",
	}

	// Forbidden import path patterns
	forbiddenPatterns := []string{
		"/internal/adapters/input/extract/",
	}

	fset := token.NewFileSet()

	for _, filename := range applyFiles {
		filepath := filepath.Join(cmdDir, filename)

		// Skip if file doesn't exist
		if _, err := os.Stat(filepath); os.IsNotExist(err) {
			continue
		}

		f, err := parser.ParseFile(fset, filepath, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s: %v", filename, err)
			continue
		}

		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)

			for _, pattern := range forbiddenPatterns {
				if strings.Contains(importPath, pattern) {
					t.Errorf("%s imports forbidden package %s (contains %q)\n"+
						"Evaluation must not depend on extractors. "+
						"Use observations contract (obs.v0.1) instead.",
						filename, importPath, pattern)
				}
			}
		}
	}
}

// TestApplyDryRunContract verifies that apply help references --dry-run.
func TestApplyDryRunContract(t *testing.T) {
	helpText := NewApplyCmd().Long
	if !strings.Contains(helpText, "--dry-run") {
		t.Error("apply help text should reference --dry-run")
	}
}

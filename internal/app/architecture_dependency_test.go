package app

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestHexagonalDependencyDirection enforces inward dependency flow:
//   - domain must not import adapters/app/cmd layers
//   - app must not import adapters/cmd layers
func TestHexagonalDependencyDirection(t *testing.T) {
	root := findModuleRoot(t)

	type rule struct {
		dirPrefix string
		forbidden []string
		allowed   []string // exceptions within forbidden prefixes
	}

	rules := []rule{
		{
			dirPrefix: filepath.Join("internal", "core"),
			forbidden: []string{
				"github.com/sufield/stave/internal/adapters/",
				"github.com/sufield/stave/internal/app",
				"github.com/sufield/stave/cmd/",
				// core/ ships vendor-neutral abstractions; provider
				// packages depend on core, never the reverse. Catches
				// regressions on the Phase 5 stage D direction reversal.
				"github.com/sufield/stave/internal/platform/providers/",
			},
		},
		{
			dirPrefix: filepath.Join("internal", "app"),
			forbidden: []string{
				"github.com/sufield/stave/internal/adapters/",
				"github.com/sufield/stave/internal/platform/",
				"github.com/sufield/stave/internal/doctor",
				"github.com/sufield/stave/cmd/",
				"os/exec",
			},
		},
		{
			dirPrefix: filepath.Join("internal", "adapters"),
			forbidden: []string{
				"github.com/sufield/stave/internal/app/",
				"github.com/sufield/stave/cmd/",
			},
			allowed: []string{
				"github.com/sufield/stave/internal/app/contracts",
			},
		},
	}

	fset := token.NewFileSet()
	var violations []string

	for _, r := range rules {
		absDir := filepath.Join(root, r.dirPrefix)
		err := filepath.WalkDir(absDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return fmt.Errorf("parse file: %w", parseErr)
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}

			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, "\"")
				for _, ban := range r.forbidden {
					if p == ban || strings.HasPrefix(p, ban) {
						isAllowed := false
						for _, allow := range r.allowed {
							if p == allow || strings.HasPrefix(p, allow) {
								isAllowed = true
								break
							}
						}
						if !isAllowed {
							violations = append(violations, rel+": imports "+p)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", absDir, err)
		}
	}

	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("hexagonal dependency violation: %s", v)
	}
}

// TestNoFloatingInternalPackages guards the layered structure of
// internal/. Top-level subdirectories under internal/ must be one
// of the declared architectural layers — anything else is a
// "floating" package that the dependency direction tests cannot
// reason about and that adds a new placement convention.
//
// Adding a layer requires updating the allow-list below; a future
// contributor cannot drop a new internal/foo/ package by accident.
func TestNoFloatingInternalPackages(t *testing.T) {
	root := findModuleRoot(t)
	internalDir := filepath.Join(root, "internal")

	allowed := map[string]bool{
		// Architectural layers tested by TestHexagonalDependencyDirection.
		"core":     true,
		"app":      true,
		"adapters": true,
		"platform": true,
		"cli":      true,

		// Cross-cutting helpers carved out by category. Each has a
		// clear scope; new floating packages are not.
		"compliance":  true, // compliance-framework metadata
		"config":      true, // CLI config-file loading
		"contracts":   true, // legacy global contracts (internal/app/contracts is the active one)
		"controldata": true, // pre-Phase-5 control data; future move into adapters/controls
		"doctor":      true, // doctor diagnostics; semi-cmd-like
		"env":         true, // env-var loading helpers
		"profile":     true, // compliance profile evaluation
		"sanitize":    true, // ID sanitisation helpers
		"testutil":    true, // shared test helpers
		"tools":       true, // build-time code-gen tools
		"util":        true, // small pure-functional utilities
		"version":     true, // version-string constants
		"yamlutil":    true, // yaml parsing helpers
	}

	entries, err := os.ReadDir(internalDir)
	if err != nil {
		t.Fatalf("read internal/: %v", err)
	}

	var floating []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !allowed[name] {
			floating = append(floating, name)
		}
	}

	sort.Strings(floating)
	for _, name := range floating {
		t.Errorf("floating internal package: internal/%s/ — assign to a layer or add to the allow-list with rationale", name)
	}
}

// TestNoVendorStringsInCore guards the vendor-neutrality of
// internal/core/. Production .go files (test files excluded) must
// not contain string literals carrying AWS-specific markers; those
// strings belong with the AWS provider package.
//
// The check is case-insensitive and operates on string-literal
// AST nodes only — comments and identifier names are ignored, so a
// docstring that says "AWS" or a function named UseAWS is fine.
func TestNoVendorStringsInCore(t *testing.T) {
	root := findModuleRoot(t)
	coreDir := filepath.Join(root, "internal", "core")

	bannedSubstrings := []string{
		"arn:aws",
		".amazonaws.com",
		".iam.gserviceaccount.com",
	}

	fset := token.NewFileSet()
	var violations []string

	walkErr := filepath.WalkDir(coreDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			return fmt.Errorf("parse file: %w", parseErr)
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			lower := strings.ToLower(lit.Value)
			for _, banned := range bannedSubstrings {
				if strings.Contains(lower, banned) {
					pos := fset.Position(lit.Pos())
					violations = append(violations,
						fmt.Sprintf("%s:%d: literal %s contains banned substring %q",
							rel, pos.Line, lit.Value, banned))
					break
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", coreDir, walkErr)
	}

	sort.Strings(violations)
	for _, v := range violations {
		t.Errorf("vendor string in core: %s", v)
	}
}

func findModuleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find module root (go.mod not found)")
		}
		dir = parent
	}
}

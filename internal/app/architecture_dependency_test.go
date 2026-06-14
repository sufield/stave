package app

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
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
			allowed: []string{
				// fsutil is a stdlib-os-equivalent filesystem-safety
				// utility (symlink-safe SafeWriteFile / SafeCreateFile),
				// not a provider or adapter. App use-cases already perform
				// direct file I/O via stdlib os (permitted — only os/exec
				// is banned); fsutil merely hardens those same writes
				// against symlink TOCTOU. Routing every write site through
				// this single utility is a deliberate security invariant,
				// so app services that persist output (attest sidecars,
				// audit bundles, exemption stores) depend on it directly.
				"github.com/sufield/stave/internal/platform/fsutil",
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

	slices.Sort(violations)
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

	allowed := map[string]struct{}{
		// Architectural layers tested by TestHexagonalDependencyDirection.
		"core":     {},
		"app":      {},
		"adapters": {},
		"platform": {},
		"cli":      {},

		// Cross-cutting helpers carved out by category. Each has a
		// clear scope; new floating packages are not.
		"compliance":  {}, // compliance-framework metadata
		"config":      {}, // CLI config-file loading
		"contracts":   {}, // legacy global contracts (internal/app/contracts is the active one)
		"controldata": {}, // pre-Phase-5 control data; future move into adapters/controls
		"doctor":      {}, // doctor diagnostics; semi-cmd-like
		"env":         {}, // env-var loading helpers
		"profile":     {}, // compliance profile evaluation
		"sanitize":    {}, // ID sanitisation helpers
		"testutil":    {}, // shared test helpers
		"tools":       {}, // build-time code-gen tools
		"util":        {}, // small pure-functional utilities
		"version":     {}, // version-string constants
		"yamlutil":    {}, // yaml parsing helpers
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
		if _, ok := allowed[name]; !ok {
			floating = append(floating, name)
		}
	}

	slices.Sort(floating)
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
			for _, banned := range bannedSubstrings {
				if containsFold(lit.Value, banned) {
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

	slices.Sort(violations)
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

func containsFold(s, substrLower string) bool {
	if substrLower == "" {
		return true
	}
	if len(s) < len(substrLower) {
		return false
	}
	for i := 0; i <= len(s)-len(substrLower); i++ {
		match := true
		for j := 0; j < len(substrLower); j++ {
			c1 := s[i+j]
			c2 := substrLower[j]
			if c1 != c2 {
				if c1 >= 'A' && c1 <= 'Z' {
					c1 += 'a' - 'A'
				}
				if c1 != c2 {
					match = false
					break
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}

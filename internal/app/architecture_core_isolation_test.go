package app

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCoreRuntimeNoHardwiredSideEffects enforces that core runtime code does not
// hardwire process/terminal side effects.
func TestCoreRuntimeNoHardwiredSideEffects(t *testing.T) {
	root := findModuleRoot(t)
	targets := []string{
		filepath.Join("pkg", "alpha", "domain"),
		filepath.Join("internal", "app"),
	}

	forbidden := []string{
		"os.Exit(",
		"fmt.Printf(",
		"fmt.Println(",
		"os.Stderr",
		"os.Stdout",
	}

	var violations []string
	for _, relDir := range targets {
		absDir := filepath.Join(root, relDir)
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

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}

			text := string(data)
			for _, pattern := range forbidden {
				if strings.Contains(text, pattern) {
					violations = append(violations, rel+": contains "+pattern)
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
		t.Errorf("core side-effect violation: %s", v)
	}
}

// TestCoreTestsAreIsolated enforces that core tests don't couple to outer layers
// (CLI frameworks, DB drivers, process exec, HTTP servers).
func TestCoreTestsAreIsolated(t *testing.T) {
	root := findModuleRoot(t)

	targets := []string{
		filepath.Join("pkg", "alpha", "domain"),
		filepath.Join("internal", "app"),
		filepath.Join("internal", "app", "service"),
	}

	forbiddenImports := []string{
		"database/sql",
		"github.com/spf13/cobra",
		"github.com/urfave/cli",
		"net/http",
		"net/http/httptest",
		"os/exec",
		"flag",
	}

	fset := token.NewFileSet()
	var violations []string

	for _, relDir := range targets {
		absDir := filepath.Join(root, relDir)
		err := filepath.WalkDir(absDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".go" || !strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}

			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, "\"")
				for _, ban := range forbiddenImports {
					if p == ban {
						violations = append(violations, rel+": imports "+p)
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
		t.Errorf("core test isolation violation: %s", v)
	}
}

package enginetest

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// TestNoBannedImportsInRuntime inspects all .go files in the runtime binary's
// package tree for imports that must never appear in the shipped binary.
// Restrictions are sourced from internal/domain/kernel/airgap.go.
// Vendored dependencies are excluded.
func TestNoBannedImportsInRuntime(t *testing.T) {
	// Excluded directories: vendored dependencies, dev tooling, and CLI
	// entrypoints not shipped as part of the runtime domain.
	excludedDirs := map[string]bool{
		"vendor":         true,
		"internal/tools": true,
		"cmd":            true,
	}

	root := findRepoRoot(t)

	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}

		// Skip non-Go files
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Skip test files
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// Get path relative to repo root for exclusion check
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if isAirgapPolicyFile(rel) {
			return nil
		}

		// Skip excluded directories
		for dir := range excludedDirs {
			if strings.HasPrefix(rel, dir+"/") || rel == dir {
				return nil
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)

		for _, banned := range kernel.DefaultPolicy().BannedImports() {
			if strings.Contains(content, banned) {
				if kernel.DefaultPolicy().IsImportAllowed(rel, banned) {
					continue
				}
				violations = append(violations, rel+": imports "+banned)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("error walking source tree: %v", err)
	}

	for _, v := range violations {
		t.Errorf("banned import found: %s", v)
	}
}

// TestOperatorList_MatchesDocumentation ensures the operator list in code
// matches the documented set. If this test fails, update both
// predicate_ops.go and docs/evaluation-semantics.md.
func TestOperatorList_MatchesDocumentation(t *testing.T) {
	// Expected operators — must match predicate.ListSupported()
	// and the Predicate Operator Reference in docs/evaluation-semantics.md.
	expected := []predicate.Operator{
		predicate.OpEq,
		predicate.OpNe,
		predicate.OpGt,
		predicate.OpLt,
		predicate.OpGte,
		predicate.OpLte,
		predicate.OpMissing,
		predicate.OpPresent,
		predicate.OpIn,
		predicate.OpListEmpty,
		predicate.OpNotSubsetOfField,
		predicate.OpNeqField,
		predicate.OpNotInField,
		predicate.OpContains,
		predicate.OpAnyMatch,
	}

	actual := predicate.ListSupported()

	expectedSorted := make([]predicate.Operator, len(expected))
	copy(expectedSorted, expected)
	slices.Sort(expectedSorted)

	if len(actual) != len(expectedSorted) {
		t.Fatalf("operator count mismatch: code has %d, test expects %d\ncode: %v\nexpected: %v",
			len(actual), len(expectedSorted), actual, expectedSorted)
	}

	for i := range actual {
		if actual[i] != expectedSorted[i] {
			t.Errorf("operator mismatch at index %d: code has %q, test expects %q",
				i, actual[i], expectedSorted[i])
		}
	}
}

// TestNoHTTPSchemaIdentifiers ensures that schema files and the validator
// do not use http:// or https:// as schema $id values, which would trigger
// false positives in security analyzers.
func TestNoHTTPSchemaIdentifiers(t *testing.T) {
	root := findRepoRoot(t)

	// Check schema.go for http(s) schema base URIs
	validatorPath := filepath.Join(root, "internal", "contracts", "validator", "schema.go")
	data, err := os.ReadFile(validatorPath)
	if err != nil {
		t.Fatalf("cannot read schema.go: %v", err)
	}
	content := string(data)
	for _, pattern := range []string{"http://", "https://"} {
		if strings.Contains(content, pattern) {
			t.Errorf("schema.go contains %q — schema identifiers must use non-network URN scheme", pattern)
		}
	}

	// Check schema JSON files for http(s) $id values
	schemaDir := filepath.Join(root, "schemas")
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatalf("cannot read schemas directory: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(schemaDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("cannot read %s: %v", entry.Name(), err)
			continue
		}
		content := string(data)
		if strings.Contains(content, `"$id": "http://`) || strings.Contains(content, `"$id": "https://`) {
			t.Errorf("%s contains HTTP(S) $id — schema identifiers must use non-network URN scheme", entry.Name())
		}
	}
}

// TestNoCredentialEnvReads inspects runtime source for references to cloud
// credential environment variables. Stave must never read credential env vars.
// Restrictions are sourced from internal/domain/kernel/airgap.go.
// The only allowed env var read is NO_COLOR.
func TestNoCredentialEnvReads(t *testing.T) {
	excludedDirs := map[string]bool{
		"vendor":         true,
		"internal/tools": true,
	}

	root := findRepoRoot(t)
	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if isAirgapPolicyFile(rel) {
			return nil
		}
		for dir := range excludedDirs {
			if strings.HasPrefix(rel, dir+"/") {
				return nil
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)

		for _, envVar := range kernel.DefaultPolicy().BannedCredentialKeys() {
			if strings.Contains(content, envVar) {
				violations = append(violations, rel+": references "+envVar)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("error walking source tree: %v", err)
	}

	for _, v := range violations {
		t.Errorf("credential env var reference found: %s", v)
	}
}

// isAirgapPolicyFile reports whether a relative path is one of the known
// air-gap policy data files that should be excluded from safety inspections.
func isAirgapPolicyFile(rel string) bool {
	return slices.Contains(kernel.DefaultPolicy().ProtectedPaths(), rel)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}

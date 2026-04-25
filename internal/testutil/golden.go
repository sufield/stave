package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// UpdateGolden reports whether golden files should be regenerated
// during this test run. Set UPDATE_GOLDEN=1 in the environment to
// enable. The variable name is intentional: it is the only mechanism
// for regenerating in-process golden files in this codebase. Per-
// package -update flags should be removed in favor of this variable.
//
// Examples:
//
//	go test ./internal/profile/reporter                          # compare only
//	UPDATE_GOLDEN=1 go test ./internal/profile/reporter           # regenerate this package
//	UPDATE_GOLDEN=1 go test ./internal/profile/reporter -run TestTextReporter_Golden
//
// The 5807 testdata/e2e fixture goldens (expected.* files) are NOT
// driven by this variable. Use `make golden-fixture FILTER=<regex>`
// to regenerate them; that path runs the stave binary per fixture
// via the regengoldens tool.
func UpdateGolden() bool {
	return os.Getenv("UPDATE_GOLDEN") != ""
}

// AssertGolden compares got against the file at path. When
// UPDATE_GOLDEN is set, it writes got to path first and only
// re-reads after the write, so the comparison still runs and any
// mid-flight transformation that breaks idempotency surfaces as a
// test failure rather than a silently-wrong golden file.
func AssertGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if UpdateGolden() {
		writeGoldenIfChanged(t, path, got)
	}

	want, err := os.ReadFile(path) //nolint:gosec // path is a test-author-supplied golden fixture path
	if err != nil {
		t.Fatalf("read golden file %s: %v\n\nRun with UPDATE_GOLDEN=1 to create it", path, err)
	}

	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Fatalf("golden mismatch %s (-want +got):\n%s\n\nRun with UPDATE_GOLDEN=1 to update", path, diff)
	}
}

// AssertGoldenString is AssertGolden for string output.
func AssertGoldenString(t *testing.T, path string, got string) {
	t.Helper()
	AssertGolden(t, path, []byte(got))
}

// writeGoldenIfChanged writes data to path only if the file is
// missing or its contents differ. The skip-when-equal path keeps
// mtimes (and therefore git status) stable when UPDATE_GOLDEN is
// set on a clean tree.
func writeGoldenIfChanged(t *testing.T, path string, data []byte) {
	t.Helper()

	old, err := os.ReadFile(path) //nolint:gosec // path is a test-author-supplied golden fixture path
	if err == nil && bytes.Equal(old, data) {
		return
	}

	// Test fixture files are intentionally world-readable so other
	// dev tools (jq, diff, the regengoldens helper) can inspect them
	// without elevated permissions.
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil { //nolint:gosec // test fixture dir
		t.Fatalf("create golden dir: %v", mkErr)
	}
	if wErr := os.WriteFile(path, data, 0o644); wErr != nil { //nolint:gosec // test fixture file
		t.Fatalf("write golden file %s: %v", path, wErr)
	}
	t.Logf("updated golden file: %s", path)
}

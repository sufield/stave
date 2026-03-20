package lint

import (
	"os"
	"path/filepath"
	"testing"
)

func writeControl(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLintDir_BadControl(t *testing.T) {
	dir := t.TempDir()
	writeControl(t, dir, "bad.yaml", `
id: CTL.INVALID
name: bad
description: bad
generated_at: now
items:
  - value: a
`)

	diags, err := LintDir(dir)
	if err != nil {
		t.Fatalf("LintDir error: %v", err)
	}

	codes := map[string]bool{}
	for _, d := range diags {
		codes[d.RuleID] = true
	}
	if !codes["CTL_ID_NAMESPACE"] {
		t.Error("expected CTL_ID_NAMESPACE diagnostic")
	}
	if !codes["CTL_NONDETERMINISTIC_FIELD"] {
		t.Error("expected CTL_NONDETERMINISTIC_FIELD diagnostic")
	}
	if !codes["CTL_ORDERING_HINT"] {
		t.Error("expected CTL_ORDERING_HINT diagnostic")
	}
	if ErrorCount(diags) == 0 {
		t.Error("expected at least one error-severity diagnostic")
	}
}

func TestLintDir_GoodControl(t *testing.T) {
	dir := t.TempDir()
	writeControl(t, dir, "good.yaml", `
dsl_version: ctrl.v1
id: CTL.AWS.PUBLIC_001.001
name: Buckets should stay private
description: Public buckets increase exposure.
type: unsafe_state
remediation:
  description: exposure exceeds safe defaults
  action: Disable public access.
unsafe_predicate:
  any:
    - id: one
      field: properties.storage.access.public_read
      op: eq
      value: true
`)

	diags, err := LintDir(dir)
	if err != nil {
		t.Fatalf("LintDir error: %v", err)
	}
	if ErrorCount(diags) > 0 {
		t.Fatalf("expected no errors for good control, got: %+v", diags)
	}
}

func TestLintDir_NoFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := LintDir(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestCollectYAMLFiles_SingleFile(t *testing.T) {
	dir := t.TempDir()
	writeControl(t, dir, "ctl.yaml", "id: test\n")

	files, err := CollectYAMLFiles(filepath.Join(dir, "ctl.yaml"))
	if err != nil {
		t.Fatalf("CollectYAMLFiles error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
}

func TestCollectYAMLFiles_UnsupportedExt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "readme.txt")
	if err := os.WriteFile(path, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := CollectYAMLFiles(path)
	if err == nil {
		t.Fatal("expected error for .txt file")
	}
}

func TestSortDiagnostics(t *testing.T) {
	diags := []Diagnostic{
		{Path: "b.yaml", Line: 1, RuleID: "R1"},
		{Path: "a.yaml", Line: 2, RuleID: "R1"},
		{Path: "a.yaml", Line: 1, RuleID: "R2"},
	}
	SortDiagnostics(diags)
	if diags[0].Path != "a.yaml" || diags[0].Line != 1 {
		t.Fatalf("expected a.yaml:1 first, got %s:%d", diags[0].Path, diags[0].Line)
	}
	if diags[1].Path != "a.yaml" || diags[1].Line != 2 {
		t.Fatalf("expected a.yaml:2 second, got %s:%d", diags[1].Path, diags[1].Line)
	}
}

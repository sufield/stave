package yaml

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/domain/kernel"
)

// TestControlLoader_RejectsMissingDSLVersion tests that LoadControls returns an error
// when an control definition is missing the required dsl_version field.
func TestControlLoader_RejectsMissingDSLVersion(t *testing.T) {
	dir := t.TempDir()
	content := `id: CTL.EXP.STATE.101
name: Test Control
description: Test
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing dsl_version")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "dsl_version") {
		t.Errorf("error should mention dsl_version, got: %s", errStr)
	}
	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %s", errStr)
	}
}

// TestControlLoader_RejectsUnsupportedDSLVersion tests that LoadControls returns an error
// when an control definition specifies an unsupported dsl_version.
func TestControlLoader_RejectsUnsupportedDSLVersion(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctl.v99.0
id: CTL.EXP.STATE.101
name: Test Control
description: Test
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for unsupported dsl_version")
	}

	// Schema validation should reject unsupported version via const constraint or version check
	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) && !strings.Contains(err.Error(), "UNSUPPORTED_SCHEMA_VERSION") {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// TestControlLoader_AcceptsSupportedDSLVersion tests that LoadControls successfully
// loads an control definition with a supported dsl_version.
func TestControlLoader_AcceptsSupportedDSLVersion(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.EXP.STATE.101
name: Test Control
description: Test
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Errorf("expected 1 control, got %d", len(controls))
	}
	if controls[0].DSLVersion != "ctrl.v1" {
		t.Errorf("expected dsl_version ctrl.v1, got %s", controls[0].DSLVersion)
	}
}

// TestControlLoader_RejectsWhitespaceType tests that schema validation rejects
// whitespace-only type values.
func TestControlLoader_RejectsWhitespaceType(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.EXP.STATE.199
name: Test Control
description: Test
type: "   "
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected semantic validation error for whitespace type")
	}
	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// TestControlLoader_RejectsMissingID tests that schema validation
// catches missing required id field.
func TestControlLoader_RejectsMissingID(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
name: Test Control
description: Test
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing id")
	}

	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// TestControlLoader_RejectsDuplicateIDs tests that LoadControls returns a hard
// error when two files in the same directory contain the same control ID.
// This is the MVP1 defense against duplicate ID collisions (Option C).
func TestControlLoader_RejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()

	inv1 := `dsl_version: ctrl.v1
id: CTL.TEST.DUP.001
name: First Definition
description: First version
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.a"
      op: "eq"
      value: true
`
	inv2 := `dsl_version: ctrl.v1
id: CTL.TEST.DUP.001
name: Second Definition
description: Duplicate ID
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.b"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "a_first.yaml"), []byte(inv1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b_second.yaml"), []byte(inv2), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for duplicate control ID")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "duplicate control ID") {
		t.Errorf("error should mention duplicate control ID, got: %s", errStr)
	}
	if !strings.Contains(errStr, "CTL.TEST.DUP.001") {
		t.Errorf("error should mention the conflicting ID, got: %s", errStr)
	}
	if !strings.Contains(errStr, "a_first.yaml") || !strings.Contains(errStr, "b_second.yaml") {
		t.Errorf("error should mention both file paths, got: %s", errStr)
	}
}

// TestControlLoader_CanonicalS3DirNoDuplicates verifies that the canonical
// controls/s3/ directory loads without duplicate ID errors.
func TestControlLoader_CanonicalS3DirNoDuplicates(t *testing.T) {
	// Path from this test file to repo root: yaml/ -> controls/ -> input/ -> adapters/ -> internal/ -> stave/
	s3Dir := filepath.Join("..", "..", "..", "..", "..", "controls", "s3")
	if _, err := os.Stat(s3Dir); os.IsNotExist(err) {
		t.Skip("controls/s3/ not found (running outside repo)")
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	controls, err := loader.LoadControls(context.Background(), s3Dir)
	if err != nil {
		t.Fatalf("canonical S3 controls failed to load: %v", err)
	}

	if len(controls) == 0 {
		t.Fatal("expected non-empty controls from canonical S3 directory")
	}

	// Verify count matches expected canonical set (35 controls after exposure extensions)
	if len(controls) < 35 {
		t.Errorf("expected at least 35 canonical S3 controls, got %d", len(controls))
	}

	// Double-check: no duplicates (the loader already enforces this, but belt-and-suspenders)
	idSet := make(map[kernel.ControlID]bool)
	for _, ctl := range controls {
		if idSet[ctl.ID] {
			t.Errorf("duplicate ID in canonical set: %s", ctl.ID)
		}
		idSet[ctl.ID] = true
	}
}

// TestControlLoader_UniqueIDsAcrossMultipleLoads verifies that loading a
// directory containing two files with the same control ID surfaces the conflict.
func TestControlLoader_UniqueIDsAcrossMultipleLoads(t *testing.T) {
	dir := t.TempDir()

	// Simulate canonical PUBLIC.001 (broad: public_read OR public_list)
	canonical := `dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: No Public S3 Buckets
description: Broad effective public access check
domain: exposure
scope_tags:
  - aws
  - s3
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.storage.access.public_read"
      op: "eq"
      value: true
    - field: "properties.storage.access.public_list"
      op: "eq"
      value: true
`
	// Simulate a duplicate PUBLIC.001 (narrow: policy-only)
	duplicate := `dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: No Public Read via Bucket Policy
description: Narrow policy-only check
domain: storage
scope_tags:
  - aws
  - s3
type: unsafe_duration
unsafe_predicate:
  any:
    - field: "properties.storage.access.public_read_via_policy"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "canonical.yaml"), []byte(canonical), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "duplicate.yaml"), []byte(duplicate), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error when two files define the same PUBLIC.001 control ID")
	}
	if !strings.Contains(err.Error(), "duplicate control ID") {
		t.Errorf("expected duplicate ID error, got: %s", err.Error())
	}
}

// TestControlLoader_LoadsRemediationField tests that the YAML loader correctly
// parses the optional remediation field into the ControlDefinition struct.
func TestControlLoader_LoadsRemediationField(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.TEST.MIT.001
name: Test Remediation
description: Test control with remediation
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
remediation:
  description: "Resource is publicly exposed."
  action: "Remove public access and enable PAB."
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}

	ctl := controls[0]
	if ctl.Remediation == nil {
		t.Fatal("expected Remediation to be non-nil")
	}
	if ctl.Remediation.Description != "Resource is publicly exposed." {
		t.Errorf("Remediation.Description = %q, want %q", ctl.Remediation.Description, "Resource is publicly exposed.")
	}
	if ctl.Remediation.Action != "Remove public access and enable PAB." {
		t.Errorf("Remediation.Action = %q, want %q", ctl.Remediation.Action, "Remove public access and enable PAB.")
	}
}

func TestControlLoader_LoadsRemediationExampleField(t *testing.T) {
	dir := t.TempDir()
	content := "dsl_version: ctrl.v1\nid: CTL.TEST.MITEX.001\nname: Test Remediation Example\ndescription: Test control with remediation example\ntype: unsafe_state\nunsafe_predicate:\n  any:\n    - field: \"properties.test\"\n      op: \"eq\"\n      value: true\nremediation:\n  description: \"Resource is publicly exposed.\"\n  action: \"Remove public access and enable PAB.\"\n  example: |\n    {\n      \"storage\": {\n        \"visibility\": {\n          \"public_read\": false\n        }\n      }\n    }\n"
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}

	ctl := controls[0]
	if ctl.Remediation == nil {
		t.Fatal("expected Remediation to be non-nil")
	}
	wantExample := "{\n  \"storage\": {\n    \"visibility\": {\n      \"public_read\": false\n    }\n  }\n}\n"
	if ctl.Remediation.Example != wantExample {
		t.Errorf("Remediation.Example = %q, want %q", ctl.Remediation.Example, wantExample)
	}
}

// TestControlLoader_RemediationOptional tests that controls without a remediation
// field load successfully with a nil Remediation pointer.
func TestControlLoader_RemediationOptional(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.TEST.NOMIT.001
name: Test No Remediation
description: Test control without remediation
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	if controls[0].Remediation != nil {
		t.Errorf("expected Remediation to be nil, got %+v", controls[0].Remediation)
	}
}

// TestControlLoader_RejectsMissingUnsafePredicate tests that schema validation
// catches missing required unsafe_predicate field.
func TestControlLoader_RejectsMissingUnsafePredicate(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.EXP.STATE.101
name: Test Control
description: Test
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing unsafe_predicate")
	}

	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// validControlYAML returns a minimal valid control YAML with the given ID.
func validControlYAML(id string) string {
	return `dsl_version: ctrl.v1
id: ` + id + `
name: Test Control
description: Test control for ` + id + `
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
}

// TestControlLoader_RecursiveLoad verifies that LoadControls loads files
// from nested subdirectories.
func TestControlLoader_RecursiveLoad(t *testing.T) {
	dir := t.TempDir()

	// Create nested subdirectory structure
	subA := filepath.Join(dir, "access")
	subB := filepath.Join(dir, "public")
	if err := os.MkdirAll(subA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subB, 0755); err != nil {
		t.Fatal(err)
	}

	// Write files in root, subA, and subB
	if err := os.WriteFile(filepath.Join(dir, "root.yaml"), []byte(validControlYAML("CTL.TEST.ROOT.001")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subA, "access.yaml"), []byte(validControlYAML("CTL.TEST.ACCESS.001")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subB, "public.yaml"), []byte(validControlYAML("CTL.TEST.PUBLIC.001")), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 3 {
		t.Errorf("expected 3 controls from recursive load, got %d", len(controls))
	}
}

// TestControlLoader_SkipsUnderscoreDirs verifies that directories prefixed
// with "_" are skipped during recursive loading.
func TestControlLoader_SkipsUnderscoreDirs(t *testing.T) {
	dir := t.TempDir()

	// Create a _registry dir with a YAML file that should be skipped
	registryDir := filepath.Join(dir, "_registry")
	if err := os.MkdirAll(registryDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(registryDir, "skip.yaml"), []byte(validControlYAML("CTL.TEST.SKIP.001")), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a normal subdir with a valid file
	normalDir := filepath.Join(dir, "normal")
	if err := os.MkdirAll(normalDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(normalDir, "keep.yaml"), []byte(validControlYAML("CTL.TEST.KEEP.001")), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 1 {
		t.Errorf("expected 1 control (skipping _registry), got %d", len(controls))
	}
	if len(controls) > 0 && controls[0].ID != "CTL.TEST.KEEP.001" {
		t.Errorf("expected CTL.TEST.KEEP.001, got %s", controls[0].ID)
	}
}

// TestControlLoader_DeterministicOrderByID verifies that loaded controls
// are sorted by ID regardless of filesystem layout.
func TestControlLoader_DeterministicOrderByID(t *testing.T) {
	dir := t.TempDir()

	// Create files in different subdirs with IDs that sort differently than paths
	subZ := filepath.Join(dir, "zzz")
	subA := filepath.Join(dir, "aaa")
	if err := os.MkdirAll(subZ, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subA, 0755); err != nil {
		t.Fatal(err)
	}

	// ID "AAA" in dir "zzz", ID "ZZZ" in dir "aaa"
	if err := os.WriteFile(filepath.Join(subZ, "z.yaml"), []byte(validControlYAML("CTL.TEST.AAA.001")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subA, "a.yaml"), []byte(validControlYAML("CTL.TEST.ZZZ.001")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mid.yaml"), []byte(validControlYAML("CTL.TEST.MMM.001")), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 3 {
		t.Fatalf("expected 3 controls, got %d", len(controls))
	}

	expected := []string{"CTL.TEST.AAA.001", "CTL.TEST.MMM.001", "CTL.TEST.ZZZ.001"}
	for i, want := range expected {
		if controls[i].ID.String() != want {
			t.Errorf("controls[%d].ID = %q, want %q", i, controls[i].ID, want)
		}
	}
}

// TestControlLoader_DuplicateIDsAcrossSubdirs verifies that duplicate IDs
// across different subdirectories produce a hard error.
func TestControlLoader_DuplicateIDsAcrossSubdirs(t *testing.T) {
	dir := t.TempDir()

	subA := filepath.Join(dir, "access")
	subB := filepath.Join(dir, "public")
	if err := os.MkdirAll(subA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subB, 0755); err != nil {
		t.Fatal(err)
	}

	// Same ID in different subdirectories
	if err := os.WriteFile(filepath.Join(subA, "a.yaml"), []byte(validControlYAML("CTL.TEST.DUP.001")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subB, "b.yaml"), []byte(validControlYAML("CTL.TEST.DUP.001")), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for duplicate control ID across subdirectories")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "duplicate control ID") {
		t.Errorf("error should mention duplicate control ID, got: %s", errStr)
	}
	if !strings.Contains(errStr, "CTL.TEST.DUP.001") {
		t.Errorf("error should mention the conflicting ID, got: %s", errStr)
	}
}

// TestControlLoader_RegistryTraversalRejected tests that loadFromRegistry rejects
// path traversal in registry index entries (e.g., "../escape.yaml").
func TestControlLoader_RegistryTraversalRejected(t *testing.T) {
	dir := t.TempDir()

	// Create _registry/controls.index.json with a traversal path
	regDir := filepath.Join(dir, "_registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}

	indexJSON := `{"schema_version":"1.0","files":["../escape.yaml"]}`
	if err := os.WriteFile(filepath.Join(regDir, "controls.index.json"), []byte(indexJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// Place a valid control outside the root to prove it's NOT loaded
	if err := os.WriteFile(filepath.Join(dir, "..", "escape.yaml"), []byte(validControlYAML("CTL.ESCAPE.001")), 0o644); err != nil {
		// May fail if parent is read-only; that's fine — the traversal check is pre-read
		t.Logf("could not create escape file (expected in sandboxed dirs): %v", err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for registry path traversal, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "traversal") && !strings.Contains(errStr, "invalid registry entry") {
		t.Errorf("error should mention traversal or invalid registry entry, got: %s", errStr)
	}
}

func TestControlLoader_UnsafePredicateAliasExpansion(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.TEST.ALIAS.001
name: Alias expansion
 description: alias expansion test
type: unsafe_state
unsafe_predicate_alias: s3.is_public_readable
`
	// normalize accidental leading space in description key alignment
	content = strings.ReplaceAll(content, "\n description:", "\ndescription:")
	if err := os.WriteFile(filepath.Join(dir, "alias.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("control count = %d, want 1", len(controls))
	}
	if len(controls[0].UnsafePredicate.Any) == 0 {
		t.Fatal("expected expanded unsafe_predicate.any rules")
	}
}

func TestControlLoader_UnsafePredicateAliasUnknown(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.TEST.ALIAS.002
name: Alias unknown
 description: alias unknown test
type: unsafe_state
unsafe_predicate_alias: s3.unknown_alias
`
	content = strings.ReplaceAll(content, "\n description:", "\ndescription:")
	if err := os.WriteFile(filepath.Join(dir, "alias_bad.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	_, err = loader.LoadControls(context.Background(), dir)
	if err == nil {
		t.Fatal("expected unknown alias error")
	}
	if !strings.Contains(err.Error(), "unknown unsafe_predicate_alias") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestControlLoader_SkipsExampleFiles verifies that .example.yaml files
// (scaffolded templates) are not loaded as live controls.
func TestControlLoader_SkipsExampleFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a valid control
	if err := os.WriteFile(filepath.Join(dir, "real.yaml"), []byte(validControlYAML("CTL.TEST.REAL.001")), 0644); err != nil {
		t.Fatal(err)
	}
	// Write an example file that would fail validation if loaded
	if err := os.WriteFile(filepath.Join(dir, "control.example.yaml"), []byte("# all comments\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Also test .example.yml variant
	if err := os.WriteFile(filepath.Join(dir, "other.example.yml"), []byte("# template\n"), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}

	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(controls) != 1 {
		t.Errorf("expected 1 control (skipping example files), got %d", len(controls))
	}
	if len(controls) > 0 && controls[0].ID != "CTL.TEST.REAL.001" {
		t.Errorf("expected CTL.TEST.REAL.001, got %s", controls[0].ID)
	}
}

func TestControlLoader_ZeroValueUsable(t *testing.T) {
	dir := t.TempDir()
	content := `dsl_version: ctrl.v1
id: CTL.EXP.STATE.101
name: Test Control
description: Test
type: unsafe_state
unsafe_predicate:
  any:
    - field: "properties.test"
      op: "eq"
      value: true
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader, err := NewControlLoader()
	if err != nil {
		t.Fatalf("NewControlLoader: %v", err)
	}
	controls, err := loader.LoadControls(context.Background(), dir)
	if err != nil {
		t.Fatalf("loader failed: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
}

package lint

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParse(t *testing.T, input string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		t.Fatalf("mustParse: %v", err)
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return &doc
}

func TestCheckID_Valid(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `id: CTL.AWS.PUBLIC.001`)
	diags := l.checkID("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
}

func TestCheckID_ValidWithoutPrefix(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `id: AWS.PUBLIC.001`)
	diags := l.checkID("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics for bare namespace, got %v", diags)
	}
}

func TestCheckID_Missing(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `name: test`)
	diags := l.checkID("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_ID_REQUIRED" {
		t.Fatalf("expected CTL_ID_REQUIRED, got %v", diags)
	}
}

func TestCheckID_BadNamespace(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `id: CTL.INVALID`)
	diags := l.checkID("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_ID_NAMESPACE" {
		t.Fatalf("expected CTL_ID_NAMESPACE, got %v", diags)
	}
}

func TestCheckMetadata_AllPresent(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
name: Test
description: A test control
remediation:
  action: Fix it
`)
	diags := l.checkMetadata("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
}

func TestCheckMetadata_MissingName(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
description: A test control
remediation:
  action: Fix it
`)
	diags := l.checkMetadata("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_META_NAME_REQUIRED" {
		t.Fatalf("expected CTL_META_NAME_REQUIRED, got %v", diags)
	}
}

func TestCheckMetadata_MissingAll(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `id: CTL.TEST.001`)
	diags := l.checkMetadata("test.yaml", root)
	if len(diags) != 3 {
		t.Fatalf("expected 3 diagnostics for missing name, description, remediation; got %d: %v", len(diags), diags)
	}
}

func TestCheckVersion_Valid(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `dsl_version: ctrl.v1`)
	diags := l.checkVersion("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
}

func TestCheckVersion_Missing(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `id: CTL.TEST.001`)
	diags := l.checkVersion("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_SCHEMA_ASSUMED_V1" {
		t.Fatalf("expected CTL_SCHEMA_ASSUMED_V1, got %v", diags)
	}
	if diags[0].Severity != SeverityWarn {
		t.Fatalf("expected warn severity, got %s", diags[0].Severity)
	}
}

func TestCheckVersion_Unsupported(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `dsl_version: inv.v0.1`)
	diags := l.checkVersion("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_SCHEMA_UNSUPPORTED" {
		t.Fatalf("expected CTL_SCHEMA_UNSUPPORTED, got %v", diags)
	}
}

func TestWalkDeterminism_Clean(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
name: test
properties:
  field: value
`)
	diags := l.walkDeterminism("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
}

func TestWalkDeterminism_Forbidden(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
name: test
generated_at: "2026-01-01"
runtime: "go1.26"
`)
	diags := l.walkDeterminism("test.yaml", root)
	if len(diags) != 2 {
		t.Fatalf("expected 2 diagnostics for generated_at and runtime, got %d: %v", len(diags), diags)
	}
	for _, d := range diags {
		if d.RuleID != "CTL_NONDETERMINISTIC_FIELD" {
			t.Errorf("expected CTL_NONDETERMINISTIC_FIELD, got %s", d.RuleID)
		}
	}
}

func TestWalkOrdering_SortedSequence(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
items:
  - id: a
    value: 1
  - id: b
    value: 2
`)
	diags := l.walkOrdering("test.yaml", root)
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics for sorted sequence, got %v", diags)
	}
}

func TestWalkOrdering_UnsortedSequence(t *testing.T) {
	l := NewLinter()
	root := mustParse(t, `
items:
  - value: a
  - value: b
`)
	diags := l.walkOrdering("test.yaml", root)
	if len(diags) != 1 || diags[0].RuleID != "CTL_ORDERING_HINT" {
		t.Fatalf("expected CTL_ORDERING_HINT, got %v", diags)
	}
}

func TestWalk_VisitsAllKeys(t *testing.T) {
	root := mustParse(t, `
top:
  nested:
    deep: value
  sibling: other
`)
	var keys []string
	walk(root, func(k, _ *yaml.Node) {
		keys = append(keys, k.Value)
	})
	expected := map[string]bool{"top": true, "nested": true, "deep": true, "sibling": true}
	for _, k := range keys {
		if !expected[k] {
			t.Errorf("unexpected key visited: %s", k)
		}
		delete(expected, k)
	}
	for k := range expected {
		t.Errorf("key not visited: %s", k)
	}
}

func TestFindNode(t *testing.T) {
	root := mustParse(t, `
name: test
value: 42
`)
	k, v := findNode(root, "name")
	if k == nil || v == nil {
		t.Fatal("expected to find 'name' node")
	}
	if v.Value != "test" {
		t.Fatalf("expected 'test', got %q", v.Value)
	}

	k, v = findNode(root, "missing")
	if k != nil || v != nil {
		t.Fatal("expected nil for missing key")
	}
}

func TestGetString(t *testing.T) {
	root := mustParse(t, `
name: hello
count: 5
`)
	val, node := getString(root, "name")
	if val != "hello" || node == nil {
		t.Fatalf("expected 'hello', got %q", val)
	}

	val, node = getString(root, "nonexistent")
	if val != "" || node != nil {
		t.Fatalf("expected empty for missing key, got %q", val)
	}
}

func TestNewDiag_BoundsCheck(t *testing.T) {
	d := newDiag("f.yaml", 0, -1, "R1", "msg", SeverityError)
	if d.Line != 1 || d.Col != 1 {
		t.Fatalf("expected line=1 col=1 for invalid input, got line=%d col=%d", d.Line, d.Col)
	}
}

func TestNodePos_Nil(t *testing.T) {
	line, col := nodePos(nil)
	if line != 1 || col != 1 {
		t.Fatalf("expected 1,1 for nil node, got %d,%d", line, col)
	}
}

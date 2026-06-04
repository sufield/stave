package forge

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalValidControl is a complete, schema-valid ctrl.v1 control that
// passes UnmarshalControlDefinition + Prepare. Copied in spirit from the
// smallest embedded control so the validate path exercises real parsing.
const minimalValidControl = `dsl_version: ctrl.v1
id: CTL.FORGE.TEST.001
name: Forge Test Control
description: Fixture control for validateGeneratedControl tests.
domain: resilience
severity: medium
type: unsafe_state
classification: state_assertion
remediation:
  description: Fix it.
  action: Do the thing.
unsafe_predicate:
  all:
  - field: properties.thing.enabled
    op: eq
    value: false
`

func writeControl(t *testing.T, dir, name, body string) {
	t.Helper()
	ctlDir := filepath.Join(dir, "fail", "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctlDir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidateGeneratedControl_ExactMatchPasses(t *testing.T) {
	out := t.TempDir()
	writeControl(t, out, "CTL.FORGE.TEST.001.yaml", minimalValidControl)

	var buf bytes.Buffer
	if err := validateGeneratedControl(&buf, "CTL.FORGE.TEST.001", out); err != nil {
		t.Fatalf("valid exact-named control must validate, got: %v\n%s", err, buf.String())
	}
}

func TestValidateGeneratedControl_SubstringSiblingNotValidated(t *testing.T) {
	// Only a sibling whose basename CONTAINS the control ID is present —
	// the exact <controlID>.yaml was never generated. The old Contains
	// match would validate this sibling; the exact match must ignore it
	// and report the missing real output as a failure.
	out := t.TempDir()
	writeControl(t, out, "CTL.FORGE.TEST.001_v2.yaml", minimalValidControl)

	var buf bytes.Buffer
	err := validateGeneratedControl(&buf, "CTL.FORGE.TEST.001", out)
	if err == nil {
		t.Fatalf("a basename-contains sibling must NOT satisfy validation; want error, got nil\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("want 'not found' error, got: %v", err)
	}
}

func TestValidateGeneratedControl_MissingYAMLFailsLoud(t *testing.T) {
	// Generation produced nothing. Must fail loud, not report SKIPPED
	// success and ship a missing control.
	out := t.TempDir()

	var buf bytes.Buffer
	err := validateGeneratedControl(&buf, "CTL.FORGE.TEST.001", out)
	if err == nil {
		t.Fatalf("missing generated YAML must return an error, got nil\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "SKIPPED") {
		t.Errorf("missing output must not be reported as SKIPPED success; output:\n%s", buf.String())
	}
}

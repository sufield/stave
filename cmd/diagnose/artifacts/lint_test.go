package artifacts

import (
	"bytes"
	"strings"
	"testing"
)

func TestLintCommand_ReportsErrorsAndWarnings(t *testing.T) {
	tmp := t.TempDir()
	writeTestFile(t, tmp+"/bad.yaml", `
id: CTL.INVALID
name: bad
description: bad
generated_at: now
items:
  - value: a
`)

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"lint", tmp})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected lint to fail")
	}
	out := buf.String()
	if !strings.Contains(out, "CTL_ID_NAMESPACE") {
		t.Fatalf("expected id namespace rule, got: %s", out)
	}
	if !strings.Contains(out, "CTL_NONDETERMINISTIC_FIELD") {
		t.Fatalf("expected nondeterministic field rule, got: %s", out)
	}
	if !strings.Contains(out, "CTL_ORDERING_HINT") {
		t.Fatalf("expected ordering hint, got: %s", out)
	}
}

func TestLintCommand_PassesForCanonicalControl(t *testing.T) {
	tmp := t.TempDir()
	writeTestFile(t, tmp+"/good.yaml", `
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

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"lint", tmp})

	if err := root.Execute(); err != nil {
		t.Fatalf("expected lint pass, got %v\noutput=%s", err, buf.String())
	}
}

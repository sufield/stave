package diagnose

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplainCommandText(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatalf("mkdir controls: %v", err)
	}

	ctl := `dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Bucket must not be public
description: Detect public read/list exposure.
type: unsafe_state
params: {}
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
    - field: properties.storage.visibility.public_list
      op: eq
      value: true
`
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.S3.PUBLIC.001.yaml"), []byte(ctl), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"explain", "CTL.S3.PUBLIC.001", "--controls", ctlDir})

	if err := root.Execute(); err != nil {
		t.Fatalf("explain command failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Matched fields:") {
		t.Fatalf("expected matched fields section, got: %s", out)
	}
	if !strings.Contains(out, "properties.storage.visibility.public_read") {
		t.Fatalf("expected public_read field, got: %s", out)
	}
	if !strings.Contains(out, `"schema_version": "obs.v0.1"`) {
		t.Fatalf("expected minimal observation snippet, got: %s", out)
	}
}

func TestExplainCommandNotFound(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatalf("mkdir controls: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"explain", "CTL.MISSING.001", "--controls", ctlDir})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing control")
	}
	if !strings.Contains(err.Error(), "Next: stave validate --controls") {
		t.Fatalf("expected next-command hint, got: %v", err)
	}
}

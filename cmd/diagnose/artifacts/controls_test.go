package artifacts

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlsListCommandText(t *testing.T) {
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
    - field: properties.storage.access.public_read
      op: eq
      value: true
`
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.S3.PUBLIC.001.yaml"), []byte(ctl), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"controls", "list", "--controls", ctlDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("controls list failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "CTL.S3.PUBLIC.001") {
		t.Fatalf("expected control id in output, got: %s", out)
	}
}

func TestControlsExplainCommand(t *testing.T) {
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
    - field: properties.storage.access.public_read
      op: eq
      value: true
`
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.S3.PUBLIC.001.yaml"), []byte(ctl), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"controls", "explain", "CTL.S3.PUBLIC.001", "--controls", ctlDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("controls explain failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Matched fields:") {
		t.Fatalf("expected explain output, got: %s", out)
	}
}

func TestControlsListCommandCSV(t *testing.T) {
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
    - field: properties.storage.access.public_read
      op: eq
      value: true
`
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.S3.PUBLIC.001.yaml"), []byte(ctl), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"controls", "list", "--controls", ctlDir, "--format", "csv", "--columns", "id,name", "--no-headers"})
	if err := root.Execute(); err != nil {
		t.Fatalf("controls list csv failed: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if out != "CTL.S3.PUBLIC.001,Bucket must not be public" {
		t.Fatalf("unexpected csv output: %q", out)
	}
}

func TestControlsListCommandInvalidColumns(t *testing.T) {
	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"controls", "list", "--columns", "id,unknown"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for invalid --columns")
	}
}

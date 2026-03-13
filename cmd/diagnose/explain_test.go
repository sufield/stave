package diagnose

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestExplainText(t *testing.T) {
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

	var buf bytes.Buffer
	explainer := NewExplainer(compose.NewDefaultProvider())
	err := explainer.Run(context.Background(), ExplainRequest{
		ControlID:   "CTL.S3.PUBLIC.001",
		ControlsDir: ctlDir,
		Format:      ui.OutputFormatText,
		Stdout:      &buf,
	})
	if err != nil {
		t.Fatalf("explain failed: %v", err)
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

func TestExplainNotFound(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "controls")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatalf("mkdir controls: %v", err)
	}

	var buf bytes.Buffer
	explainer := NewExplainer(compose.NewDefaultProvider())
	err := explainer.Run(context.Background(), ExplainRequest{
		ControlID:   "CTL.MISSING.001",
		ControlsDir: ctlDir,
		Format:      ui.OutputFormatText,
		Stdout:      &buf,
	})
	if err == nil {
		t.Fatal("expected error for missing control")
	}
	if !strings.Contains(err.Error(), "Next: stave validate --controls") {
		t.Fatalf("expected next-command hint, got: %v", err)
	}
}

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
    - field: properties.storage.access.public_read
      op: eq
      value: true
    - field: properties.storage.access.public_list
      op: eq
      value: true
`
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.S3.PUBLIC.001.yaml"), []byte(ctl), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	p := compose.NewDefaultProvider()
	repo, err := p.NewControlRepo()
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	explainer := NewExplainerWithFinder(repo)
	result, err := explainer.Run(context.Background(), ExplainRequest{
		ControlID:   "CTL.S3.PUBLIC.001",
		ControlsDir: ctlDir,
	})
	if err != nil {
		t.Fatalf("explain failed: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteExplainResult(&buf, result, ui.OutputFormatText); err != nil {
		t.Fatalf("write result: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Matched fields:") {
		t.Fatalf("expected matched fields section, got: %s", out)
	}
	if !strings.Contains(out, "properties.storage.access.public_read") {
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

	p := compose.NewDefaultProvider()
	repo, err := p.NewControlRepo()
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	explainer := NewExplainerWithFinder(repo)
	_, err = explainer.Run(context.Background(), ExplainRequest{
		ControlID:   "CTL.MISSING.001",
		ControlsDir: ctlDir,
	})
	if err == nil {
		t.Fatal("expected error for missing control")
	}
	if !strings.Contains(err.Error(), "Next: stave validate --controls") {
		t.Fatalf("expected next-command hint, got: %v", err)
	}
}

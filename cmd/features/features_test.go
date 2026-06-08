package features

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// These drive the command end-to-end (cobra Execute). The rendering and
// registry discovery now live behind stave.RenderFeatures; the renderer
// factory + payload type moved with them, so this file tests the command's
// observable behaviour rather than those internals.

func TestFeatures_TextOutput(t *testing.T) {
	cmd := NewCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"IN SCOPE", "OUT OF SCOPE", "Control Catalog", "Snapshot Generation"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestFeatures_JSONOutput(t *testing.T) {
	cmd := NewCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var p struct {
		InScope []struct {
			Label  string `json:"label"`
			Detail string `json:"detail"`
		} `json:"in_scope"`
		OutOfScope []json.RawMessage `json:"out_of_scope"`
	}
	if err := json.Unmarshal(buf.Bytes(), &p); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(p.InScope) == 0 {
		t.Error("expected discovered in-scope features")
	}
	if len(p.OutOfScope) == 0 {
		t.Error("expected out-of-scope entries")
	}
	var catalog string
	for _, f := range p.InScope {
		if f.Label == "Control Catalog" {
			catalog = f.Detail
		}
	}
	if !strings.Contains(catalog, "controls across") {
		t.Errorf("Control Catalog detail looks undiscovered: %q", catalog)
	}
}

func TestFeatures_UnknownFormat(t *testing.T) {
	cmd := NewCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--format", "xml"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestFeatures_FrameworkFlags(t *testing.T) {
	cmd := NewCmd()
	if cmd.Flags().Lookup("no-pager") == nil {
		t.Error("--no-pager flag missing")
	}
	f := cmd.Flags().Lookup("format")
	if f == nil || f.DefValue != "auto" {
		t.Errorf("--format default = %q, want \"auto\"", func() string {
			if f == nil {
				return "<nil>"
			}
			return f.DefValue
		}())
	}
}

func TestFeatures_WideHasColumns(t *testing.T) {
	cmd := NewCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "wide"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"IN SCOPE", "OUT OF SCOPE", "ALTERNATIVES", "Control Catalog"} {
		if !strings.Contains(out, want) {
			t.Errorf("wide output missing %q:\n%s", want, out)
		}
	}
}

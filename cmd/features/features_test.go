package features

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

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
	var p payload
	if err := json.Unmarshal(buf.Bytes(), &p); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(p.InScope) == 0 {
		t.Error("expected discovered in-scope features")
	}
	if len(p.OutOfScope) == 0 {
		t.Error("expected out-of-scope entries")
	}
	// The catalog detail must be discovered (real count), not a placeholder.
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

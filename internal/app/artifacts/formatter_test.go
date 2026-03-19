package artifacts

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/catalog"
)

func TestFormatJSON_Canonical(t *testing.T) {
	input := []byte(`{"schema_version":"obs.v0.1","captured_at":"2026-01-15T00:00:00Z","generated_by":{"source_type":"aws-s3-snapshot","tool":"test"},"assets":[]}`)
	out, err := FormatJSON(input)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}
	if !strings.Contains(string(out), "\n") {
		t.Fatal("expected indented output")
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}
}

func TestFormatJSON_InvalidInput(t *testing.T) {
	_, err := FormatJSON([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFormatYAML_Canonical(t *testing.T) {
	input := []byte("id: CTL.TEST.001\nname: test\n")
	out, err := FormatYAML(input)
	if err != nil {
		t.Fatalf("FormatYAML error: %v", err)
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}
}

func TestFormatYAML_InvalidInput(t *testing.T) {
	_, err := FormatYAML([]byte(":\n  - :\n    :\n: ["))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestFormatByExtension_Dispatch(t *testing.T) {
	yaml := []byte("id: test\n")

	out, err := FormatByExtension("control.yaml", yaml)
	if err != nil {
		t.Fatalf("FormatByExtension yaml: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output for .yaml")
	}

	out, err = FormatByExtension("readme.txt", yaml)
	if err != nil {
		t.Fatalf("FormatByExtension txt: %v", err)
	}
	if out != nil {
		t.Fatal("expected nil output for unrecognized extension")
	}
}

func TestFormatControlOutput_JSON(t *testing.T) {
	var buf strings.Builder
	cfg := catalog.ListConfig{Format: "json"}
	err := FormatControlOutput(&buf, cfg, nil)
	if err != nil {
		t.Fatalf("FormatControlOutput json: %v", err)
	}
}

func TestFormatControlOutput_Text(t *testing.T) {
	var buf strings.Builder
	cfg := catalog.ListConfig{Format: "text", Columns: "id,name"}
	rows := []catalog.ControlRow{{ID: "CTL.TEST.001", Name: "Test control"}}
	err := FormatControlOutput(&buf, cfg, rows)
	if err != nil {
		t.Fatalf("FormatControlOutput text: %v", err)
	}
	if !strings.Contains(buf.String(), "CTL.TEST.001") {
		t.Fatalf("expected control ID in output, got: %s", buf.String())
	}
}

package report

import (
	"bytes"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestNewRendererKnownFormats(t *testing.T) {
	cases := []struct {
		name   string
		format appcontracts.OutputFormat
		want   Renderer
	}{
		{"json", appcontracts.FormatJSON, JSONRenderer{}},
		{"text", appcontracts.FormatText, TextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) error = %v", tc.format, err)
			}
			if got != tc.want {
				t.Fatalf("NewRenderer(%q) = %T, want %T", tc.format, got, tc.want)
			}
		})
	}
}

func TestNewRendererUnknownFormat(t *testing.T) {
	r, err := NewRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatal("NewRenderer(bogus) expected error, got nil")
	}
	if r != nil {
		t.Fatalf("NewRenderer(bogus) renderer = %v, want nil", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONRendererSmoke(t *testing.T) {
	var buf bytes.Buffer
	p := reportPayload{
		Eval:         sampleEvaluation(),
		StaveVersion: "test-version",
	}
	if err := (JSONRenderer{}).Render(&buf, p); err != nil {
		t.Fatalf("JSONRenderer.Render error = %v", err)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("JSONRenderer produced empty output")
	}
	if !strings.Contains(out, "CTL.S3.PUBLIC.001") {
		t.Fatalf("JSONRenderer output missing finding: %s", out)
	}
}

func TestTextRendererSmoke(t *testing.T) {
	var buf bytes.Buffer
	p := reportPayload{
		Eval:            sampleEvaluation(),
		StaveVersion:    "test-version",
		DefaultTemplate: defaultReportTemplate,
	}
	if err := (TextRenderer{}).Render(&buf, p); err != nil {
		t.Fatalf("TextRenderer.Render error = %v", err)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("TextRenderer produced empty output")
	}
	if !strings.Contains(out, "CTL.S3.PUBLIC.001") {
		t.Fatalf("TextRenderer output missing finding: %s", out)
	}
}

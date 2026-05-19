package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
	er "github.com/sufield/stave/internal/app/execreport"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format contracts.OutputFormat
		want   any
	}{
		{contracts.FormatJSON, JSONRenderer{}},
		{contracts.FormatMarkdown, MarkdownRenderer{}},
		{"", JSONRenderer{}},
	}
	for _, tc := range cases {
		name := string(tc.format)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer(contracts.OutputFormat("yaml"))
	if err == nil {
		t.Fatalf("NewRenderer(\"yaml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	rep := &er.Report{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"markdown", MarkdownRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, rep); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

package status

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil"
	appstatus "github.com/sufield/stave/pkg/stave/status"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		name   string
		format cmdutil.OutputFormat
		want   Renderer
	}{
		{"json", cmdutil.FormatJSON, JSONRenderer{}},
		{"text", cmdutil.FormatText, TextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) error: %v", tc.format, err)
			}
			if r != tc.want {
				t.Fatalf("NewRenderer(%q) = %T, want %T", tc.format, r, tc.want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	r, err := NewRenderer(cmdutil.OutputFormat("bogus"))
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if r != nil {
		t.Fatalf("expected nil renderer for unknown format, got %T", r)
	}
}

func TestRenderers_Smoke(t *testing.T) {
	result := appstatus.Result{
		State:       appstatus.ProjectState{Root: "/tmp/project"},
		NextCommand: "stave apply",
	}
	renderers := map[string]Renderer{
		"json": JSONRenderer{},
		"text": TextRenderer{},
	}
	for name, r := range renderers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := r.Render(&buf, result); err != nil {
				t.Fatalf("Render error: %v", err)
			}
			if buf.Len() == 0 {
				t.Fatalf("expected non-empty %s output", name)
			}
		})
	}
}

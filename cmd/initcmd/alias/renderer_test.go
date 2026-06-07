package alias

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	tests := []struct {
		name   string
		format cmdutil.OutputFormat
		want   Renderer
	}{
		{name: "json", format: cmdutil.FormatJSON, want: JSONRenderer{}},
		{name: "text", format: cmdutil.FormatText, want: TextRenderer{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRenderer(tt.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) returned error: %v", tt.format, err)
			}
			if r != tt.want {
				t.Fatalf("NewRenderer(%q) = %T, want %T", tt.format, r, tt.want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	r, err := NewRenderer(cmdutil.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewRenderer(bogus) expected error, got renderer %T", r)
	}
	if r != nil {
		t.Fatalf("NewRenderer(bogus) expected nil renderer, got %T", r)
	}
}

func TestRenderers_Smoke(t *testing.T) {
	entries := []Entry{
		{Name: "ev", Command: "apply --controls controls/s3"},
		{Name: "ls", Command: "alias list"},
	}
	renderers := []struct {
		name string
		r    Renderer
	}{
		{name: "json", r: JSONRenderer{}},
		{name: "text", r: TextRenderer{}},
	}
	for _, tc := range renderers {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.r.Render(&buf, entries); err != nil {
				t.Fatalf("%s Render returned error: %v", tc.name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s Render produced empty output", tc.name)
			}
		})
	}
}

func TestRenderers_Empty(t *testing.T) {
	renderers := []struct {
		name string
		r    Renderer
	}{
		{name: "json", r: JSONRenderer{}},
		{name: "text", r: TextRenderer{}},
	}
	for _, tc := range renderers {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.r.Render(&buf, nil); err != nil {
				t.Fatalf("%s Render(nil) returned error: %v", tc.name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s Render(nil) produced empty output", tc.name)
			}
		})
	}
}

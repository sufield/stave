package path

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/attackpath"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"dot", DOTRenderer{}},
		{"csv-edges", CSVEdgesRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
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

// TestNewRenderer_EmptyAndUnknownErrors asserts that path's factory
// rejects the empty string AND unknown formats — path has no default
// human-readable format, unlike most renderers in this codebase.
func TestNewRenderer_EmptyAndUnknownErrors(t *testing.T) {
	for _, format := range []string{"", "xml", "table"} {
		t.Run(format, func(t *testing.T) {
			r, err := NewRenderer(format)
			if err == nil {
				t.Fatalf("NewRenderer(%q): want error, got %T", format, r)
			}
			if !strings.Contains(err.Error(), "unknown format") {
				t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
			}
		})
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	g := &attackpath.Graph{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"dot", DOTRenderer{}},
		{"csv-edges", CSVEdgesRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, g); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

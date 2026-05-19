package graph

import (
	"bytes"
	"strings"
	"testing"

	graphpkg "github.com/sufield/stave/internal/adapters/graph"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"stix", STIXRenderer{}},
		{"jsonld", JSONLDRenderer{}},
		{"graphml", GraphMLRenderer{}},
		{"json", JSONRenderer{}},
		{"", JSONRenderer{}},
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

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml")
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	g := &graphpkg.GraphData{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"stix", STIXRenderer{}},
		{"jsonld", JSONLDRenderer{}},
		{"graphml", GraphMLRenderer{}},
		{"json", JSONRenderer{}},
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

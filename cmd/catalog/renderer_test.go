package catalog

import (
	"bytes"
	"strings"
	"testing"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{}},
		{"", TextRenderer{}},
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
	if !strings.Contains(err.Error(), "--format must be text | json") {
		t.Errorf("error should preserve pre-migration message, got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	rep := catalogReport{
		TotalCapabilities: 0,
		Capabilities:      []appcaps.Capability{},
	}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{}},
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

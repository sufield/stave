package bisect

import (
	"bytes"
	"strings"
	"testing"

	appbisect "github.com/sufield/stave/internal/app/bisect"
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
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	// Zero-value result: no violation window, so TextRenderer returns
	// nil (not ui.ErrViolationsFound) and both renderers emit output.
	result := appbisect.Result{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := tc.renderer.Render(&stdout, &stderr, result, nil); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if stdout.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

package exportinvariants

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	t.Parallel()
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"", JSONRenderer{}},
		{"JSON", JSONRenderer{}},
		{"  json  ", JSONRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			t.Parallel()
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
	t.Parallel()
	r, err := NewRenderer("yaml")
	if err == nil {
		t.Fatalf("NewRenderer(\"yaml\"): want error, got %T", r)
	}
	// Unknown formats must wrap stave.ErrInvalidInput so the CLI
	// surface maps them to exit code 2 — same contract the previous
	// validation switch enforced.
	if !errors.Is(err, stave.ErrInvalidInput) {
		t.Errorf("error should wrap stave.ErrInvalidInput, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--format must be json") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	t.Parallel()
	out := &stave.InvariantExport{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, out); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

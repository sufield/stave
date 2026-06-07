package exportsir

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"", JSONRenderer{}},
		{"jsonl", JSONLRenderer{}},
		{"smt2", SMT2Renderer{}},
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
	r, err := NewRenderer("yaml")
	if err == nil {
		t.Fatalf("NewRenderer(\"yaml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "--format must be one of") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}

// TestJSONRenderer_NonEmptyOutput asserts the JSON renderer
// produces non-empty bytes for a minimal SIR document.
func TestJSONRenderer_NonEmptyOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONRenderer{}).Render(&buf, Payload{Doc: &sir.Document{}}); err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Errorf("Render produced empty output")
	}
}

// TestFactStreamRenderers_NoError asserts the fact-stream renderers
// return nil error. Empty fact slices may legitimately yield empty
// output, so the contract checked here is "no error", not
// "non-empty bytes".
func TestFactStreamRenderers_NoError(t *testing.T) {
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"jsonl", JSONLRenderer{}},
		{"smt2", SMT2Renderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, Payload{}); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
		})
	}
}

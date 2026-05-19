package verify

import (
	"bytes"
	"strings"
	"testing"

	av "github.com/sufield/stave/internal/app/archiveverify"
)

// TestNewRenderer_KnownFormats asserts the factory maps every
// documented format string to the right concrete type. Regression
// guard for the Renderer-pattern migration: a future rename of a
// format key must update both the help text and this map.
func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"markdown", MarkdownRenderer{}},
		{"table", TableRenderer{}},
		{"", TableRenderer{}}, // empty == default
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

// TestNewRenderer_UnknownFormatErrors asserts unknown formats become
// an explicit factory error rather than silently rendering as a
// table. This is the documented behavioural unification from
// renderer-pattern-debt.md remediation point 4.
func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml")
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got renderer %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error message should mention \"unsupported format\", got: %q", err.Error())
	}
}

// TestRenderers_NonEmptyOutput is a smoke check that each concrete
// renderer produces some bytes on a representative attestation,
// catching nil-pointer or empty-output regressions without
// asserting on exact byte content (which would couple the test to
// the renderer helpers in internal/app/archiveverify).
func TestRenderers_NonEmptyOutput(t *testing.T) {
	att := &av.Attestation{
		Verdict: av.VerdictPass,
	}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"markdown", MarkdownRenderer{}},
		{"table", TableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, att); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

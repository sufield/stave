package gate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/stave"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format contracts.OutputFormat
		want   any
	}{
		{contracts.FormatJSON, JSONRenderer{}},
		{contracts.FormatText, TextRenderer{}},
		{"", TextRenderer{}},
	}
	for _, tc := range cases {
		name := string(tc.format)
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewRenderer(tc.format, false)
			if err != nil {
				t.Fatalf("NewRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewRenderer_QuietScopedToText(t *testing.T) {
	r, err := NewRenderer(contracts.FormatText, true)
	if err != nil {
		t.Fatalf("NewRenderer(text, quiet): unexpected error: %v", err)
	}
	tr, ok := r.(TextRenderer)
	if !ok {
		t.Fatalf("NewRenderer(text) = %T, want TextRenderer", r)
	}
	if !tr.Quiet {
		t.Error("TextRenderer.Quiet should be true when quiet is requested")
	}
}

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer(contracts.OutputFormat("bogus"), false)
	if err == nil {
		t.Fatalf("NewRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	result := &stave.GateResult{
		Policy: stave.GateFailOnAnyViolation,
		Passed: true,
		Reason: "no violations",
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
			if err := tc.renderer.Render(&buf, result); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestTextRenderer_QuietSuppressesOutput(t *testing.T) {
	result := &stave.GateResult{
		Policy: stave.GateFailOnAnyViolation,
		Passed: true,
		Reason: "no violations",
	}
	var buf bytes.Buffer
	if err := (TextRenderer{Quiet: true}).Render(&buf, result); err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("quiet TextRenderer should suppress output, got %q", buf.String())
	}
}

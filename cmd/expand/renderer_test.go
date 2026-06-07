package expand

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/archetype"
	"github.com/sufield/stave/internal/app/expand"
	policy "github.com/sufield/stave/internal/core/controldef"
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
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	p := Payload{
		Archetype:      archetype.Archetype{Name: "test-archetype"},
		SnapshotStatus: &expand.SnapshotStatus{},
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
			if err := tc.renderer.Render(&buf, p); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestNewListRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", ListJSONRenderer{}},
		{"text", ListTextRenderer{}},
		{"", ListTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewListRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewListRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewListRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewListRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewListRenderer("xml")
	if err == nil {
		t.Fatalf("NewListRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestListRenderers_NonEmptyOutput(t *testing.T) {
	controls := []policy.ControlDefinition{}
	cases := []struct {
		name     string
		renderer ListRenderer
	}{
		{"json", ListJSONRenderer{}},
		{"text", ListTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, controls); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

package apply

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/findingfilter"
)

func TestNewNewOnlyRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", NewOnlyJSONRenderer{}},
		{"text", NewOnlyTextRenderer{}},
		{"", NewOnlyTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewNewOnlyRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewNewOnlyRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewNewOnlyRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewNewOnlyRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewNewOnlyRenderer("xml")
	if err == nil {
		t.Fatalf("NewNewOnlyRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestNewOnlyRenderers_NonEmptyOutput(t *testing.T) {
	res := &findingfilter.Result{}
	cases := []struct {
		name     string
		renderer NewOnlyRenderer
	}{
		{"json", NewOnlyJSONRenderer{}},
		{"text", NewOnlyTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, res); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

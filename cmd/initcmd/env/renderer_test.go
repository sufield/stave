package env

import (
	"bytes"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		name   string
		format appcontracts.OutputFormat
		want   Renderer
	}{
		{"json", appcontracts.FormatJSON, JSONRenderer{}},
		{"text", appcontracts.FormatText, TextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) returned error: %v", tc.format, err)
			}
			if r != tc.want {
				t.Fatalf("NewRenderer(%q) = %T, want %T", tc.format, r, tc.want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	r, err := NewRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatal("NewRenderer(bogus) expected error, got nil")
	}
	if r != nil {
		t.Fatalf("NewRenderer(bogus) expected nil renderer, got %T", r)
	}
}

func TestRenderers_Smoke(t *testing.T) {
	entries := []Entry{
		{
			Name:        "STAVE_EXAMPLE",
			Description: "an example var",
			Category:    "config",
			Value:       "v",
			IsSet:       true,
		},
	}
	formats := []appcontracts.OutputFormat{appcontracts.FormatJSON, appcontracts.FormatText}
	for _, f := range formats {
		t.Run(f.String(), func(t *testing.T) {
			r, err := NewRenderer(f)
			if err != nil {
				t.Fatalf("NewRenderer(%q): %v", f, err)
			}
			var buf bytes.Buffer
			if err := r.Render(&buf, entries); err != nil {
				t.Fatalf("Render(%q): %v", f, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("Render(%q) produced empty output", f)
			}
		})
	}
}

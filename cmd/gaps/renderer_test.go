package gaps

import (
	"bytes"
	"strings"
	"testing"

	appgaps "github.com/sufield/stave/internal/app/gaps"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		topN   int
	}{
		{"json", 5},
		{"text", 5},
		{"", 3},
		{"text", 0},
	}
	for _, tc := range cases {
		name := tc.format
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewRenderer(tc.format, tc.topN)
			if err != nil {
				t.Fatalf("NewRenderer(%q, %d): unexpected error: %v", tc.format, tc.topN, err)
			}
			switch tc.format {
			case "json":
				if _, ok := r.(JSONRenderer); !ok {
					t.Errorf("NewRenderer(%q) = %T, want JSONRenderer", tc.format, r)
				}
			default:
				got, ok := r.(TextRenderer)
				if !ok {
					t.Fatalf("NewRenderer(%q) = %T, want TextRenderer", tc.format, r)
				}
				if got.TopN != tc.topN {
					t.Errorf("TopN: got %d, want %d", got.TopN, tc.topN)
				}
			}
		})
	}
}

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml", 5)
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "--format must be text | json") {
		t.Errorf("error should preserve pre-migration message, got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	rep := appgaps.Report{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{TopN: 5}},
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

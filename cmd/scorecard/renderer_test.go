package scorecard

import (
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appsc "github.com/sufield/stave/internal/app/scorecard"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   Renderer
	}{
		{appcontracts.FormatJSON, JSONRenderer{}},
		{appcontracts.FormatMarkdown, MarkdownRenderer{}},
		{appcontracts.FormatTable, TableRenderer{}},
		{appcontracts.FormatText, TableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format.String(), func(t *testing.T) {
			got, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) returned error: %v", tc.format, err)
			}
			if got != tc.want {
				t.Fatalf("NewRenderer(%q) = %T, want %T", tc.format, got, tc.want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	r, err := NewRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewRenderer(bogus) = %v, want error", r)
	}
	if r != nil {
		t.Fatalf("NewRenderer(bogus) renderer = %v, want nil", r)
	}
}

func TestRenderers_Smoke(t *testing.T) {
	report := appsc.Compute(nil, []string{"hipaa", "soc2"})

	renderers := map[string]Renderer{
		"json":     JSONRenderer{},
		"markdown": MarkdownRenderer{},
		"table":    TableRenderer{},
	}
	for name, r := range renderers {
		t.Run(name, func(t *testing.T) {
			var buf strings.Builder
			if err := r.Render(&buf, report); err != nil {
				t.Fatalf("%s Render returned error: %v", name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s Render produced empty output", name)
			}
		})
	}
}

package doctor

import (
	"bytes"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/setup"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format appcontracts.OutputFormat
		want   Renderer
	}{
		{name: "json", format: appcontracts.FormatJSON, want: JSONRenderer{}},
		{name: "text", format: appcontracts.FormatText, want: TextRenderer{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q) returned error: %v", tc.format, err)
			}
			if got, want := typeName(r), typeName(tc.want); got != want {
				t.Fatalf("NewRenderer(%q) = %s, want %s", tc.format, got, want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	t.Parallel()

	r, err := NewRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewRenderer(bogus) = %v, want error", r)
	}
	if r != nil {
		t.Fatalf("NewRenderer(bogus) returned non-nil renderer %v", r)
	}
}

func TestRenderers_Smoke(t *testing.T) {
	t.Parallel()

	resp := setup.DoctorResponse{
		AllPassed: true,
		Checks: []setup.DoctorCheck{
			{Name: "git", Status: outcome.Pass, Message: "found", Fix: ""},
			{Name: "aws-cli", Status: outcome.Warn, Message: "missing", Fix: "install awscli"},
		},
	}

	renderers := []struct {
		name     string
		renderer Renderer
	}{
		{name: "json", renderer: JSONRenderer{}},
		{name: "text", renderer: TextRenderer{}},
	}

	for _, tc := range renderers {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, resp); err != nil {
				t.Fatalf("%s Render returned error: %v", tc.name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s Render produced empty output", tc.name)
			}
		})
	}
}

// typeName returns a stable identifier for a Renderer's concrete type.
func typeName(r Renderer) string {
	switch r.(type) {
	case JSONRenderer:
		return "JSONRenderer"
	case TextRenderer:
		return "TextRenderer"
	default:
		return "unknown"
	}
}

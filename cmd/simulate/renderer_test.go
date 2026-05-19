package simulate

import (
	"bytes"
	"strings"
	"testing"

	appsim "github.com/sufield/stave/internal/app/simulate"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{Fix: []string{"CTL.A.001"}}},
		{"", TextRenderer{Fix: []string{"CTL.A.001"}}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewRenderer(tc.format, []string{"CTL.A.001"})
			if err != nil {
				t.Fatalf("NewRenderer(%q): unexpected error: %v", tc.format, err)
			}
			switch want := tc.want.(type) {
			case JSONRenderer:
				if _, ok := r.(JSONRenderer); !ok {
					t.Errorf("NewRenderer(%q) = %T, want JSONRenderer", tc.format, r)
				}
			case TextRenderer:
				got, ok := r.(TextRenderer)
				if !ok {
					t.Errorf("NewRenderer(%q) = %T, want TextRenderer", tc.format, r)
					return
				}
				if strings.Join(got.Fix, ",") != strings.Join(want.Fix, ",") {
					t.Errorf("Fix list: got %v, want %v", got.Fix, want.Fix)
				}
			}
		})
	}
}

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml", nil)
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	result := &appsim.Result{
		ScoreCurrent:    70,
		ScoreSimulated:  85,
		ScoreDelta:      15,
		FindingsRemoved: 3,
	}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{Fix: []string{"CTL.A.001", "CTL.B.002"}}},
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

// TestTextRenderer_IncludesFixHeader verifies the text renderer
// names the input fix list in its header. Behavioural regression
// guard for the migration that threaded opts.Fix through the
// renderer constructor.
func TestTextRenderer_IncludesFixHeader(t *testing.T) {
	r := TextRenderer{Fix: []string{"CTL.X.001"}}
	var buf bytes.Buffer
	if err := r.Render(&buf, &appsim.Result{}); err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Fixing: CTL.X.001") {
		t.Errorf("output should include `Fixing: CTL.X.001`, got:\n%s", buf.String())
	}
}

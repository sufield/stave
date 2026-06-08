package stave

import (
	"errors"
	"testing"
)

// TestRenderScorecard_Formats exercises the renderers that moved here
// from cmd/scorecard. An assessment with zero findings is a legitimate
// all-passing input; every format must still produce output.
func TestRenderScorecard_Formats(t *testing.T) {
	data := []byte(`{"findings":[]}`)
	for _, format := range []string{"json", "markdown", "table", "text", ""} {
		out, err := RenderScorecard(data, []string{"hipaa", "soc2"}, format)
		if err != nil {
			t.Fatalf("RenderScorecard(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("RenderScorecard(%q): produced empty output", format)
		}
	}
}

func TestRenderScorecard_UnsupportedFormat(t *testing.T) {
	_, err := RenderScorecard([]byte(`{"findings":[]}`), nil, "bogus")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unsupported format should wrap ErrInvalidInput, got: %v", err)
	}
}

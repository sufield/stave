package stave

import (
	"strings"
	"testing"

	appcoverage "github.com/sufield/stave/internal/app/coverage"
)

// TestRenderCoverageMap covers the ATT&CK coverage renderers that moved
// here from cmd/map: all four formats must produce non-empty output for an
// empty report, and an unsupported format must error.
func TestRenderCoverageMap(t *testing.T) {
	rep := &appcoverage.CoverageReport{}
	for _, format := range []string{"json", "navigator", "markdown", "table", ""} {
		out, err := renderCoverageMap(rep, format)
		if err != nil {
			t.Fatalf("renderCoverageMap(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("renderCoverageMap(%q): produced empty output", format)
		}
	}
}

func TestRenderCoverageMap_UnsupportedFormat(t *testing.T) {
	_, err := renderCoverageMap(&appcoverage.CoverageReport{}, "xml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

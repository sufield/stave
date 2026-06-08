package stave

import (
	"testing"

	"github.com/sufield/stave/internal/app/fieldcov"
)

// TestRenderFieldCoverage covers the coverage renderers that moved here
// from cmd/coverage: both formats must produce non-empty output for an
// empty report.
func TestRenderFieldCoverage(t *testing.T) {
	rep := &fieldcov.Report{}
	for _, format := range []string{"json", "table", ""} {
		out, err := renderFieldCoverage(rep, format)
		if err != nil {
			t.Fatalf("renderFieldCoverage(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("renderFieldCoverage(%q): produced empty output", format)
		}
	}
}

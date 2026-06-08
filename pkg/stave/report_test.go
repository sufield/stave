package stave

import (
	"strings"
	"testing"

	er "github.com/sufield/stave/internal/app/execreport"
)

// TestRenderReport covers the executive-report renderers that moved here
// from cmd/report: both formats must produce non-empty output for an empty
// report, and an unsupported format must error.
func TestRenderReport(t *testing.T) {
	rep := &er.Report{}
	for _, format := range []string{"json", "markdown", ""} {
		out, err := renderReport(rep, format)
		if err != nil {
			t.Fatalf("renderReport(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("renderReport(%q): produced empty output", format)
		}
	}
}

func TestRenderReport_UnsupportedFormat(t *testing.T) {
	_, err := renderReport(&er.Report{}, "yaml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

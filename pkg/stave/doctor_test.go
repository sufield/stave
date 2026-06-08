package stave

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/setup"
)

// TestRenderDoctor covers the doctor renderers that moved here from
// cmd/doctor: both formats must produce non-empty output for a report with
// at least one check, and an unknown format must error.
func TestRenderDoctor(t *testing.T) {
	resp := setup.DoctorResponse{
		AllPassed: true,
		Checks: []setup.DoctorCheck{
			{Name: "git", Status: outcome.Pass, Message: "found", Fix: ""},
			{Name: "jq", Status: outcome.Warn, Message: "missing", Fix: "brew install jq"},
		},
	}
	for _, format := range []string{"json", "text", ""} {
		out, err := renderDoctor(resp, format)
		if err != nil {
			t.Fatalf("renderDoctor(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("renderDoctor(%q): produced empty output", format)
		}
	}
	if !bytes.Contains(mustRenderDoctor(t, resp, "text"), []byte("Fix: brew install jq")) {
		t.Error("text render should include the fix line")
	}
}

func mustRenderDoctor(t *testing.T, resp setup.DoctorResponse, format string) []byte {
	t.Helper()
	out, err := renderDoctor(resp, format)
	if err != nil {
		t.Fatalf("renderDoctor: %v", err)
	}
	return out
}

func TestRenderDoctor_UnknownFormat(t *testing.T) {
	if _, err := renderDoctor(setup.DoctorResponse{}, "bogus"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

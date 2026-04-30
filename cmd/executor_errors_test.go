package cmd

import (
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// TestSentinelTemplatesCoverEveryExitCode asserts that every exit
// code reachable through ui.IsSentinel has a presentation template.
// Adding a new sentinel exit code without a matching template would
// regress the user-facing error rendering to the generic
// "Command failed" path; this test catches that gap at build time.
func TestSentinelTemplatesCoverEveryExitCode(t *testing.T) {
	required := []int{
		ui.ExitInputError,
		ui.ExitViolations,
		ui.ExitSecurity,
		ui.ExitInternal,
		ui.ExitInterrupted,
	}
	for _, code := range required {
		if _, ok := sentinelTemplates[code]; !ok {
			t.Errorf("sentinelTemplates missing entry for exit code %d", code)
		}
	}
}

func TestSentinelTemplate_Internal_RenderingFields(t *testing.T) {
	tmpl, ok := sentinelTemplates[ui.ExitInternal]
	if !ok {
		t.Fatal("ExitInternal template missing")
	}
	if tmpl.Title == "" || tmpl.Action == "" {
		t.Errorf("ExitInternal template incomplete: %+v", tmpl)
	}
}

func TestSentinelTemplate_Interrupted_RenderingFields(t *testing.T) {
	tmpl, ok := sentinelTemplates[ui.ExitInterrupted]
	if !ok {
		t.Fatal("ExitInterrupted template missing")
	}
	if tmpl.Title == "" || tmpl.Action == "" {
		t.Errorf("ExitInterrupted template incomplete: %+v", tmpl)
	}
}

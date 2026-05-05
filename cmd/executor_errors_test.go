package cmd

import (
	"errors"
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

// TestSentinelErrorRendering exercises errorInfoFromError end-to-end
// for every sentinel error variant so a future template field rename
// or rendering-pipeline change is caught at build time, not at the
// next operator-visible error.
//
// ErrDiagnosticsFound shares the ExitViolations exit code (and template)
// with ErrViolationsFound — see ui.ExitCode. Both are listed so a
// future split that gives diagnostics its own template/exit code shows
// up here as a test failure rather than silently changing operator
// behaviour.
func TestSentinelErrorRendering(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		wantTitle    string
		wantExitCode int
	}{
		{"violations", ui.ErrViolationsFound, "Violations detected", ui.ExitViolations},
		{"diagnostics", ui.ErrDiagnosticsFound, "Violations detected", ui.ExitViolations},
		{"security audit", ui.ErrSecurityAuditFindings, "Security audit gate failed", ui.ExitSecurity},
		{"interrupted", ui.ErrInterrupted, "Interrupted", ui.ExitInterrupted},
		{"internal", ui.ErrInternal, "Internal error", ui.ExitInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !ui.IsSentinel(tc.err) {
				t.Fatalf("test setup: %q is not a sentinel error", tc.err)
			}
			if got := ui.ExitCode(tc.err); got != tc.wantExitCode {
				t.Errorf("ExitCode = %d, want %d", got, tc.wantExitCode)
			}
			info := (&App{}).errorInfoFromError(tc.err, tc.err.Error())
			if info == nil {
				t.Fatalf("errorInfoFromError returned nil for sentinel %v", tc.err)
			}
			if info.Title != tc.wantTitle {
				t.Errorf("Title = %q, want %q", info.Title, tc.wantTitle)
			}
			if info.Action == "" {
				t.Errorf("Action is empty — operator gets no remediation hint")
			}
			if info.Code == "" {
				t.Errorf("Code is empty — telemetry consumers cannot bucket the error")
			}
		})
	}
}

// TestUserErrorRendering covers the *ui.UserError branch in
// errorInfoFromError separately from sentinel errors. UserError is
// the input-validation path that does not flow through sentinel
// templates but still needs to render correctly.
func TestUserErrorRendering(t *testing.T) {
	ue := &ui.UserError{Err: errors.New("missing required flag --foo")}
	info := (&App{}).errorInfoFromError(ue, ue.Error())
	if info == nil {
		t.Fatal("errorInfoFromError returned nil for UserError")
	}
	if info.Title != "Input validation failed" {
		t.Errorf("Title = %q, want \"Input validation failed\"", info.Title)
	}
	if info.Code != ui.CodeInvalidInput {
		t.Errorf("Code = %q, want %q", info.Code, ui.CodeInvalidInput)
	}
}

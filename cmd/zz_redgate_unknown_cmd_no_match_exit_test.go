package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// Test_RedGate_UnknownCmdNoMatchExit pins the CORRECT behavior for an
// unknown subcommand that has NO close fuzzy match (e.g. `stave zzzzqqqwww`).
//
// suggestCommandIfUnknown (cmd/executor.go) only wraps the Cobra
// "unknown command" error in *ui.UserError — which ui.ExitCode maps to
// ExitInputError (2) — when SuggestCommandError returns a NEW error
// (a close fuzzy match was found). When NO close match exists,
// SuggestCommandError returns the ORIGINAL Cobra error unchanged, the
// `enhanced != err` branch is skipped, and the raw error is returned
// verbatim. That raw error is neither a sentinel nor a *UserError, so
// ui.ExitCode falls through to ExitInternal (4).
//
// Both cases are the same class of user error — a mistyped command name —
// so both MUST exit 2 (INVALID_INPUT). The exit code must not depend on
// whether the typo happens to land within the suggest edit-distance
// threshold of a real subcommand.
//
// Against current code the no-match path returns an error mapping to
// ExitInternal (4), so this test goes RED.
func Test_RedGate_UnknownCmdNoMatchExit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in suggestCommandIfUnknown: %v", r)
		}
	}()

	// Build a root with a few visible subcommands so
	// collectVisibleCommandNames returns real candidate names.
	root := &cobra.Command{Use: "stave"}
	root.AddCommand(&cobra.Command{Use: "apply"})
	root.AddCommand(&cobra.Command{Use: "validate"})
	root.AddCommand(&cobra.Command{Use: "version"})

	app := &App{Root: root}

	// Cobra emits this exact error shape for an unknown subcommand.
	// "zzzzqqqwww" has no close fuzzy match against the real commands,
	// so SuggestCommandError returns this error unchanged (verified by
	// ui.TestSuggestCommandError_NoMatch with the same shape).
	cobraErr := errors.New(`unknown command "zzzzqqqwww" for "stave"`)

	got := app.suggestCommandIfUnknown(cobraErr)

	// A mistyped command name is invalid INPUT, not an internal fault.
	wantExit := ui.ExitInputError // 2
	gotExit := ui.ExitCode(got)
	if gotExit != wantExit {
		t.Fatalf(
			"unknown command with no fuzzy match exited %d (%s), want %d (INVALID_INPUT)\n"+
				"a typo must yield exit 2 regardless of edit-distance to a real command;\n"+
				"returned error = %v",
			gotExit, exitName(gotExit), wantExit, got,
		)
	}
}

func exitName(code int) string {
	switch code {
	case ui.ExitSuccess:
		return "SUCCESS"
	case ui.ExitSecurity:
		return "SECURITY"
	case ui.ExitInputError:
		return "INVALID_INPUT"
	case ui.ExitViolations:
		return "VIOLATIONS"
	case ui.ExitInternal:
		return "INTERNAL_ERROR"
	case ui.ExitInterrupted:
		return "INTERRUPTED"
	default:
		return "UNKNOWN"
	}
}

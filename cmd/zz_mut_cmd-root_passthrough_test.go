package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

// Test_Mut_SuggestCommandIfUnknown_NonUnknownPassthrough pins the
// passthrough contract of suggestCommandIfUnknown (cmd/executor.go) for an
// error that is NOT a Cobra "unknown command" error.
//
// suggestCommandIfUnknown reclassifies an error as *ui.UserError (exit 2,
// INVALID_INPUT) only when it is a mistyped command name — either because
// SuggestCommandError produced an enhanced "Did you mean?" error
// (enhanced != err) OR because the raw error carries the "unknown command "
// prefix (isUnknownCommandError). Any OTHER error — a real internal failure
// such as a config-load fault — must be returned UNCHANGED so ui.ExitCode
// classifies it as ExitInternal (4), not ExitInputError (2). Misclassifying
// genuine internal faults as user input errors would hide real bugs behind a
// "you typed it wrong" exit code.
//
// This test guards the `enhanced != err` half of the fix-site condition
//
//	if enhanced != err || isUnknownCommandError(err) { ... wrap ... }
//
// The CONDITIONALS_NEGATION mutant that flips `!=` to `==` survives the
// existing unknown-command tests (where isUnknownCommandError is true, so the
// OR short-circuits true either way). It only becomes observable here: for a
// non-unknown error the original yields false||false=false (passthrough),
// while the mutant yields true||false=true (wraps in *ui.UserError → exit 2).
func Test_Mut_SuggestCommandIfUnknown_NonUnknownPassthrough(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in suggestCommandIfUnknown: %v", r)
		}
	}()

	// Visible subcommands so collectVisibleCommandNames returns real
	// candidate names and SuggestCommandError actually attempts a match.
	root := &cobra.Command{Use: "stave"}
	root.AddCommand(&cobra.Command{Use: "apply"})
	root.AddCommand(&cobra.Command{Use: "lint"})
	root.AddCommand(&cobra.Command{Use: "version"})

	app := &App{Root: root}

	// A genuine internal-fault error: NOT an "unknown command" message, so
	// SuggestCommandError leaves it untouched and isUnknownCommandError is
	// false. The correct outcome is verbatim passthrough.
	internalErr := errors.New("load project config: permission denied")

	got := app.suggestCommandIfUnknown(internalErr)

	// Must NOT have been reclassified as a user input error.
	if _, ok := errors.AsType[*ui.UserError](got); ok {
		t.Fatalf(
			"non-unknown-command error was wrapped as *ui.UserError; a genuine "+
				"internal fault must not be downgraded to user-input class\n"+
				"returned error = %v",
			got,
		)
	}

	// And it must map to ExitInternal (4), not ExitInputError (2).
	wantExit := ui.ExitInternal // 4
	gotExit := ui.ExitCode(got)
	if gotExit != wantExit {
		t.Fatalf(
			"non-unknown-command error exited %d (%s), want %d (INTERNAL_ERROR)\n"+
				"only mistyped command names may map to exit 2; every other error "+
				"must stay an internal fault\nreturned error = %v",
			gotExit, exitName(gotExit), wantExit, got,
		)
	}
}

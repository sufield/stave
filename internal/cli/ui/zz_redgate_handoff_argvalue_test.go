package ui

import (
	"testing"
)

// Test_RedGate_HandoffArgValue asserts the CORRECT behavior for
// runtime.go:174 ShouldShowWorkflowHandoff: the ignore set
// {-h,--help,help,--version,version,completion,status} is meant to match
// the INVOKED COMMAND (help/version/completion/status pages have no
// follow-up workflow), not a flag VALUE or positional argument.
//
// Current code iterates over EVERY element of args and returns false if
// ANY element is in the ignore set. So a normal `apply` run whose flag
// value happens to equal an ignored token (e.g. an observations directory
// literally named "status") incorrectly suppresses the
// "Next workflow start: ..." hint.
//
// This test FAILS against current code because the args list contains the
// bare word "status" as a flag VALUE, which the over-broad match treats
// as the invoked command.
func Test_RedGate_HandoffArgValue(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	// `stave apply --observations status ./controls`: a real evaluation
	// run where "status" is the VALUE of --observations, not a subcommand.
	args := []string{"apply", "--observations", "status", "./obs"}

	if !ShouldShowWorkflowHandoff(args) {
		t.Fatalf("ShouldShowWorkflowHandoff(%v) = false, want true: a real `apply` run whose "+
			"flag VALUE equals an ignored token (\"status\") must still show the workflow "+
			"handoff hint; the ignore set should match the invoked command, not arg values",
			args)
	}

	// Sanity anchor: the genuine command-page invocations the ignore set
	// is FOR must still be suppressed, so the fix is a value/command
	// distinction rather than removing the ignore set entirely.
	for _, blocked := range [][]string{{"status"}, {"help"}, {"--version"}} {
		if ShouldShowWorkflowHandoff(blocked) {
			t.Fatalf("ShouldShowWorkflowHandoff(%v) = true, want false (anchor: command-page invocations stay suppressed)", blocked)
		}
	}
}

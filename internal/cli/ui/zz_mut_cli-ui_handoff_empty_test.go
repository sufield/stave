package ui

import (
	"testing"
)

// Test_Mut_HandoffEmptyArgs pins the boundary behavior of
// ShouldShowWorkflowHandoff (runtime.go:189) for an EMPTY args slice.
//
// The guard is `if len(args) > 0 { ... ignore[args[0]] ... }`. The length
// check is what makes `args[0]` safe: with zero args there is no invoked
// command to look up, so the function must skip the ignore-set check and
// fall through to the default (show the handoff hint).
//
// A CONDITIONALS_BOUNDARY mutation `len(args) > 0` -> `len(args) >= 0`
// makes the guard true for the empty slice, which then evaluates
// `args[0]` on a zero-length slice and panics with index-out-of-range.
// The original code returns true cleanly. No existing test exercises the
// empty-args path, so the boundary mutant survives.
//
// This test distinguishes mutant from original: the original returns true
// without panicking; the mutant panics. It asserts a real contract — when
// no command token is present the workflow handoff defaults to shown.
func Test_Mut_HandoffEmptyArgs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ShouldShowWorkflowHandoff(nil/empty) panicked: %v; the len(args) > 0 "+
				"guard must protect the args[0] lookup", r)
		}
	}()

	if got := ShouldShowWorkflowHandoff([]string{}); !got {
		t.Fatalf("ShouldShowWorkflowHandoff([]) = false, want true: with no invoked command " +
			"the handoff hint defaults to shown")
	}

	// nil slice is the same boundary condition; it must behave identically
	// and not panic.
	if got := ShouldShowWorkflowHandoff(nil); !got {
		t.Fatalf("ShouldShowWorkflowHandoff(nil) = false, want true")
	}
}

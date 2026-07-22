package cmd

import "testing"

func TestWireCommands_NoError(t *testing.T) {
	_, err := NewApp()
	if err != nil {
		t.Fatalf("NewApp() failed: %v", err)
	}
}

func TestWireCommands_CommandCount(t *testing.T) {
	root := GetTestRootCmd()
	got := len(root.Commands())
	// Update this constant when adding or removing a root command.
	// This is intentional friction to ensure awareness of tree changes.
	// 56 includes the hidden gen-man command (man-page generation).
	// 57 after adding `compliance`.
	// 58 after adding `pack` (concern packs — list/show + apply --pack).
	// 59 after adding `discover` (service-keyed pack lookup → collection manifest).
	// 60 after adding `plan` (coverage preview by service × severity).
	// 61 after adding `transform` (raw AWS snapshots → obs.v0.1, built-in jq).
	// 62 after promoting `catalog` to top-level (was capabilities-only).
	// 63 after adding `services` (AWS service registry).
	// 64 after adding `scan` (service-grouped evaluation pipeline).
	// 63 after removing `scan` — its logic moved to `apply --auto`.
	// 64 after adding `prove` (Z3 SMT formal verification).
	// 65 after adding `recommend` (template recommendation engine).
	// 66 after adding `template` (init/new/verify/eject subcommands).
	// 67 after adding `render` (JSON data + Go template = output).
	// 68 after adding `toolmap` (offensive tool prerequisite mapping).
	const want = 68
	if got != want {
		t.Errorf("root command count = %d, want %d; update this constant if a command was added/removed", got, want)
	}
}

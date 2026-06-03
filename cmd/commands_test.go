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
	const want = 55
	if got != want {
		t.Errorf("root command count = %d, want %d; update this constant if a command was added/removed", got, want)
	}
}

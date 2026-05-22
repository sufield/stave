package cmd

import "testing"

func TestRootHelpGroupsAssigned(t *testing.T) {
	// Use a fresh tree per call: tests in this package share
	// GetTestRootCmd, but Cobra's Find() result for duplicate-named
	// commands (e.g. top-level `report` vs `diagnose report`) can
	// drift when multiple tests interleave their walks against the
	// same instance. A fresh wiring is cheap enough not to matter.
	root := getRootCmd()
	if len(root.Groups()) == 0 {
		t.Fatal("expected root command groups to be configured")
	}

	checks := map[string]string{
		"generate": groupGettingStarted,
		"validate": groupCore,
		"apply":    groupCore,
		"diagnose": groupCore,
		"explain":  groupCore,
		"ci":       groupWorkflow,
		"snapshot": groupWorkflow,
		"status":   groupWorkflow,
		"enforce":  groupArtifacts,
		"report":   groupArtifacts,
		"config":   groupSettings,
	}

	for use, wantGroup := range checks {
		cmd, _, err := root.Find([]string{use})
		if err != nil {
			t.Fatalf("expected command %q: %v", use, err)
		}
		if cmd.GroupID != wantGroup {
			t.Fatalf("command %q group=%q, want %q", use, cmd.GroupID, wantGroup)
		}
	}
}

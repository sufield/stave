package cmd

import "testing"

func TestRootHelpGroupsAssigned(t *testing.T) {
	root := GetRootCmd()
	if len(root.Groups()) == 0 {
		t.Fatal("expected root command groups to be configured")
	}

	checks := map[string]string{
		"init":     groupGettingStarted,
		"generate": groupGettingStarted,
		"validate": groupCore,
		"apply":    groupCore,
		"diagnose": groupCore,
		"explain":  groupCore,
		"verify":   groupCore,
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

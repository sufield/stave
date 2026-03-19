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

func TestDevHelpGroupsAssigned(t *testing.T) {
	root := GetDevRootCmd()

	devChecks := map[string]string{
		"doctor":         groupDevTools,
		"bug-report":     groupDevTools,
		"prompt":         groupDevTools,
		"trace":          groupDevTools,
		"controls":       groupDevTools,
		"packs":          groupDevTools,
		"graph":          groupDevTools,
		"lint":           groupDevTools,
		"fmt":            groupDevTools,
		"docs":           groupDevTools,
		"alias":          groupDevTools,
		"schemas":        groupDevTools,
		"capabilities":   groupDevTools,
		"security-audit": groupDevTools,
		"version":        groupDevTools,
	}

	for use, wantGroup := range devChecks {
		cmd, _, err := root.Find([]string{use})
		if err != nil {
			t.Fatalf("expected dev command %q: %v", use, err)
		}
		if cmd.GroupID != wantGroup {
			t.Fatalf("dev command %q group=%q, want %q", use, cmd.GroupID, wantGroup)
		}
	}
}

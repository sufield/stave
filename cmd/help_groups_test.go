package cmd

import "testing"

func TestRootHelpGroupsAssigned(t *testing.T) {
	root := getRootCmd()
	if len(root.Groups()) == 0 {
		t.Fatal("expected root command groups to be configured")
	}

	checks := map[string]string{
		// Evaluate
		"apply":    groupEvaluate,
		"plan":     groupEvaluate,
		"lint":     groupEvaluate,
		"check":    groupEvaluate,
		"diagnose": groupEvaluate,
		"explain":  groupEvaluate,
		"expand":   groupEvaluate,
		"bisect":   groupEvaluate,
		// Data
		"discover":  groupData,
		"transform": groupData,
		"snapshot":  groupData,
		"readiness": groupData,
		"gaps":      groupData,
		"coverage":  groupData,
		"sanitize":  groupData,
		"contract":  groupData,
		"vet":       groupData,
		// Controls
		"controls":  groupControls,
		"test":      groupControls,
		"cel":       groupControls,
		"template":  groupControls,
		"pack":      groupControls,
		"catalog":   groupControls,
		"search":    groupControls,
		"recommend": groupControls,
		"forge":     groupControls,
		// Compliance
		"compliance": groupCompliance,
		"score":      groupCompliance,
		"scorecard":  groupCompliance,
		"profile":    groupCompliance,
		"exempt":     groupCompliance,
		"trend":      groupCompliance,
		"compare":    groupCompliance,
		"map":        groupCompliance,
		// Artifacts
		"report":    groupArtifacts,
		"export":    groupArtifacts,
		"enforce":   groupArtifacts,
		"bundle":    groupArtifacts,
		"attest":    groupArtifacts,
		"telemetry": groupArtifacts,
		"metrics":   groupArtifacts,
		"render":    groupArtifacts,
		// Analysis
		"inspect":     groupAnalysis,
		"graph":       groupAnalysis,
		"permissions": groupAnalysis,
		"fingerprint": groupAnalysis,
		"prove":       groupAnalysis,
		// Setup
		"status":       groupSetup,
		"doctor":       groupSetup,
		"version":      groupSetup,
		"config":       groupSetup,
		"ci":           groupSetup,
		"capabilities": groupSetup,
		"features":     groupSetup,
		"alias":        groupSetup,
		"generate":     groupSetup,
		"completion":   groupSetup,
	}

	for use, wantGroup := range checks {
		cmd, _, err := root.Find([]string{use})
		if err != nil {
			t.Errorf("expected command %q: %v", use, err)
			continue
		}
		if cmd == nil || cmd == root {
			t.Errorf("command %q not found", use)
			continue
		}
		if cmd.GroupID != wantGroup {
			t.Errorf("command %q group=%q, want %q", use, cmd.GroupID, wantGroup)
		}
	}
}

func TestNoUngroupedVisibleCommands(t *testing.T) {
	root := getRootCmd()
	for _, cmd := range root.Commands() {
		if cmd.Hidden || cmd.Name() == "help" {
			continue
		}
		if cmd.GroupID == "" {
			t.Errorf("visible command %q has no help group", cmd.Name())
		}
	}
}

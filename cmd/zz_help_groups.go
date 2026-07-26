package cmd

import "github.com/spf13/cobra"

// wireHelpGroups assigns every registered subcommand to one of seven
// intent-based help groups. assignCommandGroup soft-skips subcommands
// not present in this build (edition-stripped case).
func wireHelpGroups(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: groupEvaluate, Title: "Evaluate"},
		&cobra.Group{ID: groupData, Title: "Data"},
		&cobra.Group{ID: groupControls, Title: "Controls"},
		&cobra.Group{ID: groupCompliance, Title: "Compliance"},
		&cobra.Group{ID: groupArtifacts, Title: "Artifacts"},
		&cobra.Group{ID: groupAnalysis, Title: "Analysis"},
		&cobra.Group{ID: groupSetup, Title: "Setup & Config"},
	)

	groupMap := map[string][]string{
		groupEvaluate: {
			"plan", "apply", "validate", "check",
			"diagnose", "explain", "expand", "bisect",
		},
		groupData: {
			"discover", "transform", "snapshot", "readiness",
			"gaps", "coverage", "sanitize", "contract",
			"validate-mapping",
		},
		groupControls: {
			"controls", "lint", "fmt", "test", "cel",
			"template", "pack", "catalog", "search",
			"recommend", "forge",
		},
		groupCompliance: {
			"compliance", "score", "scorecard", "profile",
			"exempt", "trend", "compare", "map",
		},
		groupArtifacts: {
			"report", "export", "enforce", "bundle",
			"attest", "telemetry", "metrics", "render",
		},
		groupAnalysis: {
			"inspect", "graph", "permissions", "fingerprint", "prove",
		},
		groupSetup: {
			"status", "doctor", "version", "config",
			"capabilities", "features", "ci", "alias",
			"generate", "services",
		},
	}
	for groupID, names := range groupMap {
		for _, name := range names {
			assignCommandGroup(root, name, groupID)
		}
	}
	assignCommandGroup(root, "completion", groupSetup)
	root.SetHelpCommandGroupID(groupSetup)
}

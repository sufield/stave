package cmd

import "github.com/spf13/cobra"

func wireHelpGroups(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: groupGettingStarted, Title: "Getting Started"},
		&cobra.Group{ID: groupCore, Title: "Control Engine"},
		&cobra.Group{ID: groupWorkflow, Title: "Workflow & CI"},
		&cobra.Group{ID: groupArtifacts, Title: "Data & Artifacts"},
		&cobra.Group{ID: groupUtilities, Title: "Utilities & Help"},
	)

	groupMap := map[string][]string{
		groupGettingStarted: {"doctor", "demo", "init", "quickstart", "generate"},
		groupCore:           {"validate", "lint", "fmt", "apply", "diagnose", "verify", "explain", "trace"},
		groupWorkflow:       {"snapshot", "ci", "plan", "context", "status", "security-audit"},
		groupArtifacts:      {"ingest", "controls", "packs", "enforce", "extractor", "graph", "report"},
		groupUtilities:      {"docs", "bug-report", "capabilities", "config", "version", "alias", "prompt", "fix", "env", "schemas"},
	}
	for groupID, names := range groupMap {
		for _, name := range names {
			assignCommandGroup(root, name, groupID)
		}
	}

	root.SetCompletionCommandGroupID(groupUtilities)
	root.SetHelpCommandGroupID(groupUtilities)
}

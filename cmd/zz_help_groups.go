package cmd

import "github.com/spf13/cobra"

func wireProdHelpGroups(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: groupGettingStarted, Title: "Getting Started"},
		&cobra.Group{ID: groupCore, Title: "Control Engine"},
		&cobra.Group{ID: groupWorkflow, Title: "Workflow & CI"},
		&cobra.Group{ID: groupArtifacts, Title: "Data & Artifacts"},
		&cobra.Group{ID: groupSettings, Title: "Settings"},
	)

	groupMap := map[string][]string{
		groupGettingStarted: {"init", "generate"},
		groupCore:           {"validate", "apply", "diagnose", "explain", "verify"},
		groupWorkflow:       {"ci", "snapshot", "status"},
		groupArtifacts:      {"ingest", "enforce", "report"},
		groupSettings:       {"config"},
	}
	for groupID, names := range groupMap {
		for _, name := range names {
			assignCommandGroup(root, name, groupID)
		}
	}

	root.SetCompletionCommandGroupID(groupSettings)
	root.SetHelpCommandGroupID(groupSettings)
}

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

	assignCommandGroup(root, "doctor", groupGettingStarted)
	assignCommandGroup(root, "demo", groupGettingStarted)
	assignCommandGroup(root, "init", groupGettingStarted)
	assignCommandGroup(root, "quickstart", groupGettingStarted)
	assignCommandGroup(root, "generate", groupGettingStarted)

	assignCommandGroup(root, "validate", groupCore)
	assignCommandGroup(root, "lint", groupCore)
	assignCommandGroup(root, "fmt", groupCore)
	assignCommandGroup(root, "apply", groupCore)
	assignCommandGroup(root, "diagnose", groupCore)
	assignCommandGroup(root, "verify", groupCore)
	assignCommandGroup(root, "explain", groupCore)
	assignCommandGroup(root, "trace", groupCore)

	assignCommandGroup(root, "snapshot", groupWorkflow)
	assignCommandGroup(root, "ci", groupWorkflow)
	assignCommandGroup(root, "plan", groupWorkflow)
	assignCommandGroup(root, "context", groupWorkflow)
	assignCommandGroup(root, "status", groupWorkflow)
	assignCommandGroup(root, "security-audit", groupWorkflow)

	assignCommandGroup(root, "ingest", groupArtifacts)
	assignCommandGroup(root, "controls", groupArtifacts)
	assignCommandGroup(root, "packs", groupArtifacts)
	assignCommandGroup(root, "enforce", groupArtifacts)
	assignCommandGroup(root, "extractor", groupArtifacts)
	assignCommandGroup(root, "graph", groupArtifacts)
	assignCommandGroup(root, "report", groupArtifacts)

	assignCommandGroup(root, "docs", groupUtilities)
	assignCommandGroup(root, "bug-report", groupUtilities)
	assignCommandGroup(root, "capabilities", groupUtilities)
	assignCommandGroup(root, "config", groupUtilities)
	assignCommandGroup(root, "version", groupUtilities)
	assignCommandGroup(root, "alias", groupUtilities)
	assignCommandGroup(root, "prompt", groupUtilities)
	assignCommandGroup(root, "fix", groupUtilities)
	assignCommandGroup(root, "env", groupUtilities)
	assignCommandGroup(root, "schemas", groupUtilities)

	root.SetCompletionCommandGroupID(groupUtilities)
	root.SetHelpCommandGroupID(groupUtilities)
}

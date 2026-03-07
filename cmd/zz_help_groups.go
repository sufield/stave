package cmd

import "github.com/spf13/cobra"

func init() {
	// This file intentionally runs late in lexical init order so grouping is
	// applied after all commands have been registered.
	RootCmd.AddGroup(
		&cobra.Group{ID: groupGettingStarted, Title: "Getting Started"},
		&cobra.Group{ID: groupCore, Title: "Control Engine"},
		&cobra.Group{ID: groupWorkflow, Title: "Workflow & CI"},
		&cobra.Group{ID: groupArtifacts, Title: "Data & Artifacts"},
		&cobra.Group{ID: groupUtilities, Title: "Utilities & Help"},
	)

	assignRootCommandGroup("doctor", groupGettingStarted)
	assignRootCommandGroup("demo", groupGettingStarted)
	assignRootCommandGroup("init", groupGettingStarted)
	assignRootCommandGroup("quickstart", groupGettingStarted)
	assignRootCommandGroup("generate", groupGettingStarted)

	assignRootCommandGroup("validate", groupCore)
	assignRootCommandGroup("lint", groupCore)
	assignRootCommandGroup("fmt", groupCore)
	assignRootCommandGroup("apply", groupCore)
	assignRootCommandGroup("diagnose", groupCore)
	assignRootCommandGroup("verify", groupCore)
	assignRootCommandGroup("explain", groupCore)
	assignRootCommandGroup("trace", groupCore)

	assignRootCommandGroup("snapshot", groupWorkflow)
	assignRootCommandGroup("ci", groupWorkflow)
	assignRootCommandGroup("plan", groupWorkflow)
	assignRootCommandGroup("context", groupWorkflow)
	assignRootCommandGroup("status", groupWorkflow)
	assignRootCommandGroup("security-audit", groupWorkflow)

	assignRootCommandGroup("ingest", groupArtifacts)
	assignRootCommandGroup("controls", groupArtifacts)
	assignRootCommandGroup("packs", groupArtifacts)
	assignRootCommandGroup("enforce", groupArtifacts)
	assignRootCommandGroup("extractor", groupArtifacts)
	assignRootCommandGroup("graph", groupArtifacts)
	assignRootCommandGroup("report", groupArtifacts)

	assignRootCommandGroup("docs", groupUtilities)
	assignRootCommandGroup("bug-report", groupUtilities)
	assignRootCommandGroup("capabilities", groupUtilities)
	assignRootCommandGroup("config", groupUtilities)
	assignRootCommandGroup("version", groupUtilities)
	assignRootCommandGroup("alias", groupUtilities)
	assignRootCommandGroup("prompt", groupUtilities)
	assignRootCommandGroup("fix", groupUtilities)
	assignRootCommandGroup("env", groupUtilities)
	assignRootCommandGroup("schemas", groupUtilities)

	RootCmd.SetCompletionCommandGroupID(groupUtilities)
	RootCmd.SetHelpCommandGroupID(groupUtilities)
}

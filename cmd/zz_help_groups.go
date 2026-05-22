package cmd

import "github.com/spf13/cobra"

// wireHelpGroups assigns each registered subcommand to the help group
// it belongs to. assignCommandGroup itself soft-skips subcommands not
// present in this build (edition-stripped case) and surfaces wiring
// regressions via slog.Warn, so this wrapper has nothing to bubble
// up — every outcome is recoverable at startup.
func wireHelpGroups(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: groupGettingStarted, Title: "Getting Started"},
		&cobra.Group{ID: groupCore, Title: "Control Engine"},
		&cobra.Group{ID: groupWorkflow, Title: "Workflow & CI"},
		&cobra.Group{ID: groupArtifacts, Title: "Data & Artifacts"},
		&cobra.Group{ID: groupIntrospection, Title: "Introspection"},
		&cobra.Group{ID: groupSettings, Title: "Settings"},
	)

	// Top-level commands grouped for the help layout. `init` is intentionally
	// absent: there is no top-level `init` command in any current edition
	// (the closest is `sla init`, a subcommand). Listing it here triggered
	// a soft-skip slog.Warn on every `stave --help` invocation.
	groupMap := map[string][]string{
		groupGettingStarted: {"generate"},
		groupCore:           {"validate", "apply", "diagnose", "explain", "expand"},
		groupWorkflow:       {"ci", "snapshot", "status"},
		groupArtifacts:      {"enforce", "report"},
		groupIntrospection:  {"inspect", "features"},
		groupSettings:       {"config"},
	}
	for groupID, names := range groupMap {
		for _, name := range names {
			assignCommandGroup(root, name, groupID)
		}
	}
	assignCommandGroup(root, "completion", groupSettings)
	root.SetHelpCommandGroupID(groupSettings)
}

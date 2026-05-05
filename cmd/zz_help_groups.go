package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// wireHelpGroups assigns each registered subcommand to the help group
// it belongs to. Returns an error when the wiring is inconsistent
// (a named subcommand isn't registered, the command tree was
// corrupted) so startup fails fast instead of producing a help page
// with silently-misgrouped commands.
func wireHelpGroups(root *cobra.Command) error {
	root.AddGroup(
		&cobra.Group{ID: groupGettingStarted, Title: "Getting Started"},
		&cobra.Group{ID: groupCore, Title: "Control Engine"},
		&cobra.Group{ID: groupWorkflow, Title: "Workflow & CI"},
		&cobra.Group{ID: groupArtifacts, Title: "Data & Artifacts"},
		&cobra.Group{ID: groupIntrospection, Title: "Introspection"},
		&cobra.Group{ID: groupSettings, Title: "Settings"},
	)

	groupMap := map[string][]string{
		groupGettingStarted: {"init", "generate"},
		groupCore:           {"validate", "apply", "diagnose", "explain", "expand", "verify"},
		groupWorkflow:       {"ci", "snapshot", "status"},
		groupArtifacts:      {"enforce", "report"},
		groupIntrospection:  {"inspect"},
		groupSettings:       {"config"},
	}
	// Collect every assignment failure rather than bailing on the
	// first — operators should see the full picture when help wiring
	// regresses, not a single error followed by hidden ones the next
	// startup uncovers.
	var errs []error
	for groupID, names := range groupMap {
		for _, name := range names {
			if err := assignCommandGroup(root, name, groupID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := assignCommandGroup(root, "completion", groupSettings); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("wireHelpGroups: %w", errors.Join(errs...))
	}
	root.SetHelpCommandGroupID(groupSettings)
	return nil
}

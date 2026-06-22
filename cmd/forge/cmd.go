// Package forge implements the stave forge command group for interactive
// custom control authoring, property path discovery, and live predicate preview.
package forge

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
)

// NewCmd creates the forge parent command with new, preview, and paths subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forge",
		Short: "Author and test custom controls",
		Long: `Interactive tools for creating, previewing, and testing custom
security controls.

Subcommands:
  new       Interactive control authoring wizard
  preview   Evaluate a predicate against a snapshot without writing files
  paths     List available observation property paths from a snapshot`,
		// Control authoring is a developer-workflow command; the production
		// guard rejects it (and its subcommands) when production is detected.
		Annotations:   map[string]string{cmdutil.AnnotationDevOnly: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newPathsCmd())
	cmd.AddCommand(newPreviewCmd())
	cmd.AddCommand(newNewCmd())
	cmd.AddCommand(newTestCmd())
	cmd.AddCommand(newLintCmd())
	cmd.AddCommand(newScaffoldCmd())
	cmd.AddCommand(newChainCmd())

	return cmd
}

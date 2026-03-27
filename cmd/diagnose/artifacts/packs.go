package artifacts

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/artifacts"
	"github.com/sufield/stave/internal/metadata"
)

// NewPacksCmd constructs the packs command tree.
func NewPacksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "packs",
		Short: "Inspect built-in control packs",
		Long:  "Packs lists and shows embedded control packs available for deterministic offline evaluation." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newPacksListCmd())
	cmd.AddCommand(newPacksShowCmd())

	return cmd
}

func newPacksListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available built-in packs",
		Long: `List all built-in control packs embedded in the binary. Each pack
is a curated set of controls for a specific domain (e.g. s3).

Exit Codes:
  0    Success
  4    Internal error`,
		Example: `  stave packs list
  stave packs list --output json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runner, err := artifacts.NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.List()
		},
	}
}

func newPacksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one built-in pack and its control IDs",
		Long: `Show details of a single built-in control pack including its
control IDs, version, and description.

Exit Codes:
  0    Success
  2    Unknown pack name
  4    Internal error`,
		Example: `  stave packs show s3
  stave packs show s3 --output json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runner, err := artifacts.NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.Show(args[0])
		},
	}
}

//go:build stavedev

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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runner, err := artifacts.NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.List(cmd.Context())
		},
	}
}

func newPacksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one built-in pack and its control IDs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runner, err := artifacts.NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.Show(cmd.Context(), args[0])
		},
	}
}

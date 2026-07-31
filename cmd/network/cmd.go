package network

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/network/enumerate"
	"github.com/sufield/stave/cmd/network/prove"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the `stave network` parent command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Network reachability analysis and safety proofs",
		Long: `Analyzes network topology from observation snapshots to enumerate
entry points and formally verify routing properties.

Subcommands:
  enumerate   List all SSH paths to production hosts
  prove       Verify a network safety property (e.g., bastion routing)` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(enumerate.NewCmd())
	cmd.AddCommand(prove.NewCmd())
	return cmd
}

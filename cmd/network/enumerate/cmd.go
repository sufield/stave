package enumerate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the `stave network enumerate` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate SSH entry points to production hosts",
		Long: `Enumerates all network paths from non-production sources to production
hosts on a given port by traversing security group rules.

Production hosts are identified by the tag stave:environment=production.
Bastion hosts are identified by the tag stave:role=bastion.

Inputs:
  --observations, -o  Observation snapshots directory (required)
  --port              Port to enumerate (default: 22)
  --format, -f        Output format: json, text (default: text)

Outputs:
  stdout: list of (source, destination, port, path_type) tuples

Exit codes:
  0   Enumeration completed successfully
  2   Input error (bad flags, missing observations)
  4   Internal error
  130 Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Enumerate all SSH paths to production hosts
  stave network enumerate -o observations

  # Enumerate on a custom port, JSON output
  stave network enumerate -o observations --port 2222 -f json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

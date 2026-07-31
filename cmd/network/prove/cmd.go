package prove

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the `stave network prove` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Verify a network safety property",
		Long: `Proves a network safety property against observation snapshots.

The bastion-ssh property verifies that every SSH path to a production
host traverses a bastion node. If a bypass path exists, the specific
counterexample is produced (source, destination, violating SG rule).

Properties:
  bastion-ssh   All SSH to production routes through a bastion host

Inputs:
  --observations, -o  Observation snapshots directory (required)
  --property          Safety property to verify (default: bastion-ssh)
  --port              Port to verify (default: 22)
  --format, -f        Output format: json, text (default: text)

Outputs:
  stdout: proof result (UNSAT = property holds, SAT = bypass found)

Exit codes:
  0   Proof completed successfully (regardless of SAT/UNSAT)
  2   Input error (bad flags, missing observations)
  4   Internal error
  130 Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Verify bastion SSH routing
  stave network prove -o observations --property bastion-ssh

  # JSON output
  stave network prove -o observations -f json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

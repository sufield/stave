// Package plan implements `stave plan` — a coverage preview of which controls
// would evaluate for a set of AWS services (or a pack), broken down by service
// and severity. It is a read-only view over pack resolution; it never evaluates
// anything and never touches AWS.
package plan

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the `stave plan` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Preview which controls will evaluate, by service and severity",
		Long: `Preview what Stave will check before you collect anything. Given the AWS
services you use (or a pack), it shows the controls that would evaluate, broken
down by service and severity, plus a severity-weighted collection order so you
start with the highest-impact data first.

This is a coverage preview — distinct from "stave apply --dry-run", which checks
whether an already-collected snapshot is READY to evaluate. Use plan to decide
what to collect; use apply --dry-run to confirm a collected snapshot is complete.

Inputs:  --services (comma-separated) OR --pack <name>; --format, -f (text|json);
         --controls, -i (catalog to resolve against).
Outputs: a per-service control/severity table and recommended collection order.

Exit codes: 0 = success, 2 = input error, 4 = internal.`,
		Example: `  # What will Stave check for these services?
  stave plan --services iam,s3,ec2

  # Preview a named pack
  stave plan --pack entropy --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

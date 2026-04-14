// Package nep implements the stave nep command for querying net effective
// permissions from observation snapshots. Resolves all six AWS IAM policy
// layers to show what principals can actually do and who can reach sensitive
// resources.
package nep

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the nep command tree with principal, resource, and
// summary subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nep",
		Short: "Query net effective permissions from a snapshot",
		Long: `Resolve and display net effective permissions (NEP) by evaluating all
six AWS IAM policy layers: explicit denies, SCPs, permission boundaries,
identity-based policies, resource-based policies, and transitive role
chains.

All computation runs locally against a snapshot file. No cloud credentials
required.

Subcommands:
  principal   Resolve permissions for a specific principal ARN
  resource    Show who has effective access to a resource
  summary     Aggregate NEP metrics across all principals

Exit Codes:
  0   No findings above threshold
  1   Critical findings exist
  2   High findings (no critical)
  3   Incomplete resolution (snapshot data missing)
  4   Internal error

Examples:
  # Who can access the PHI bucket?
  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records

  # What can this role actually do?
  stave nep principal --snapshot obs.json --principal arn:aws:iam::123:role/app

  # NEP summary for CI/CD gating
  stave nep summary --snapshot obs.json --threshold critical`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newPrincipalCmd())
	cmd.AddCommand(newResourceCmd())
	cmd.AddCommand(newSummaryCmd())

	return cmd
}

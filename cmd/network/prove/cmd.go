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

Returns UNSAT if the property holds (no violating paths), SAT with
a counterexample identifying the specific violation, or EVIDENCE_GATED
when a path reaches a route target the snapshot cannot resolve.

Properties:
  bastion-ssh          All SSH to production routes through a bastion host
  prod-dev-isolation   No network path between production and development VPCs
  database-isolation   No cross-VPC or internet path to database-tier hosts
  firewall-mandatory   All private subnet internet traffic passes through Network Firewall
  transitive-ssh       No SSH path from external to internal via an intermediate host
  transitive-egress    Proves no tag-isolated workload reaches the internet via a host
                       with default-route egress. Network-layer only; IAM-layer service
                       paths are not evaluated. EVIDENCE_GATED means a path reaches a
                       route target the snapshot cannot resolve (TGW, VPN/DX, firewall
                       or GWLB endpoint, NAT instance); the result names the observation
                       that would settle it.

Inputs:
  --observations, -o  Observation snapshots directory (required)
  --property          Safety property to verify (default: bastion-ssh)
  --port              Port to verify for bastion-ssh (default: 22)
  --format, -f        Output format: json, text (default: text)

Outputs:
  stdout: proof result (UNSAT = property holds, SAT = violation found,
          EVIDENCE_GATED = inconclusive, additional observation needed)

Exit codes:
  0   Proof completed successfully (regardless of SAT/UNSAT/EVIDENCE_GATED)
  2   Input error (bad flags, missing observations)
  4   Internal error
  130 Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Verify bastion SSH routing
  stave network prove -o observations --property bastion-ssh

  # Verify environment isolation
  stave network prove -o observations --property prod-dev-isolation

  # Verify database tier isolation
  stave network prove -o observations --property database-isolation -f json

  # Verify firewall enforcement
  stave network prove -o observations --property firewall-mandatory`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

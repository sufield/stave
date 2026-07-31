package prove

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the `stave prove` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Run Z3 SMT queries against a Stave assessment",
		Long: `Prove loads observation snapshots, compiles them into a Z3 SMT model, and
runs a formal verification query. The model covers IAM policies (identity,
resource, KMS key, trust), asset relationships, and control invariants.

Queries:
  compatibility   Can principal X perform action Y on resource Z?
  reachability    Can principal X reach resource Y through any chain of
                  role assumptions and policy grants?
  conflict        Do the loaded policies contradict each other?
  choke-point     What is the minimum set of statements whose removal
                  breaks a reachability path?
  invariant       Is a control's unsafe condition reachable for ANY input?

Inputs:
  --observations, -o  Observation snapshots directory (required)
  --query             Query to run (required)
  --controls, -i      Control definitions directory (default: built-in catalog)
  --principal         Principal ARN (compatibility, reachability, choke-point)
  --action            Action (compatibility)
  --resource          Resource ARN (compatibility, reachability, choke-point)
  --invariant         Control ID (invariant query)
  --format, -f        Output format: json (default), text
  --certificate       Write SMT-LIB proof certificate to this path
  --compliance        Compliance frameworks to map (comma-separated, or 'all')
  --history           Append result to proof history JSONL in this directory

Outputs:
  stdout: query result as JSON (or text with --format text)
  certificate: self-contained SMT-LIB file verifiable by z3/cvc5/yices-smt2

Exit codes:
  0   Query completed successfully
  2   Input error (bad flags, missing observations)
  4   Internal error (Z3 not available, load failure)
  130 Interrupted (SIGINT)

Requires: binary built with -tags 'cgo z3' and libz3 installed.` + metadata.OfflineHelpSuffix,
		Example: `  # Can this role read from this bucket?
  stave prove -o observations --query compatibility \
    --principal arn:aws:iam::123456789012:role/MyRole \
    --action s3:GetObject \
    --resource arn:aws:s3:::my-bucket

  # Is there any attack path from user to bucket?
  stave prove -o observations --query reachability \
    --principal arn:aws:iam::123456789012:user/attacker \
    --resource arn:aws:s3:::sensitive-data

  # Do any policies contradict each other?
  stave prove -o observations --query conflict

  # Verify a control holds for ALL possible inputs
  stave prove -o observations --query invariant \
    --invariant CTL.S3.PUBLIC.001

  # Find the minimum fix to break an attack path
  stave prove -o observations --query choke-point \
    --principal arn:aws:iam::123456789012:user/attacker \
    --resource arn:aws:s3:::sensitive-data

  # Produce a proof certificate for independent verification
  stave prove -o observations --query compatibility \
    --principal arn:aws:iam::123456789012:role/MyRole \
    --action s3:GetObject \
    --resource arn:aws:s3:::my-bucket \
    --certificate proof.smt2
  # Then: z3 proof.smt2

  # Map proof to compliance frameworks
  stave prove -o observations --query compatibility \
    --principal arn:aws:iam::123456789012:role/MyRole \
    --action s3:GetObject \
    --resource arn:aws:s3:::my-bucket \
    --compliance pci-dss-4.0,hipaa

  # Accumulate proof history
  stave prove -o observations --query compatibility \
    --principal arn:aws:iam::123456789012:role/MyRole \
    --action s3:GetObject \
    --resource arn:aws:s3:::my-bucket \
    --certificate ./proofs/proof.smt2 \
    --history ./proofs/ \
    --compliance all`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	cmd.AddCommand(NewHistoryCmd())
	return cmd
}

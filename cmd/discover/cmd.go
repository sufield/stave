// Package discover implements `stave discover` — the service-keyed lookup axis
// over the pack system. Given the AWS services an adopter uses, it resolves the
// packs covering those services and emits their merged collection manifest, so
// the adopter never needs to know snapshot/observation internals.
package discover

import (
	"errors"

	"github.com/spf13/cobra"
)

var errNoServices = errors.New("--services is required (e.g. --services iam,s3,ec2)")

// NewCmd constructs the `stave discover` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Resolve AWS services to the data Stave needs (the collection manifest)",
		Long: `Discover what Stave needs from you. Tell it which AWS services you use; it
resolves the packs covering those services and merges their requirements into a
single collection manifest — the exact read-only API calls, observation signals,
and minimum collector IAM permissions to gather.

"Service groups" are not a new concept: a pack is a named group of controls with
a requirements manifest, and a service is just a different lookup key into the
same packs. discover is the by-service axis; "stave pack show <name>" is the
by-name axis. Both produce the same manifest model.

Stave never collects data or calls AWS. discover tells you WHAT to collect; you
collect it with your own tools (AWS CLI, Steampipe, …) and run "stave apply".

Inputs:  --services (required, comma-separated); --format, -f (text|json);
         --controls, -i (catalog to resolve against).
Outputs: the merged collection manifest on stdout.

Exit codes: 0 = success, 2 = input error (no services/bad format), 4 = internal.`,
		Example: `  # I use IAM, S3, EC2, Lambda and CloudTrail — what does Stave need?
  stave discover --services iam,s3,ec2,lambda,cloudtrail

  # Machine-readable manifest for CI
  stave discover --services iam,s3 --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

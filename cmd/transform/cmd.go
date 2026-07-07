// Package transform implements `stave transform` — the built-in converter from
// raw AWS CLI snapshots to obs.v0.1 observations. It runs jq filters in-process
// (no external jq, no cloud calls) and scrubs sensitive values, so adopters get
// evaluable observations without writing an extractor.
package transform

import (
	"github.com/spf13/cobra"
)

// NewCmd constructs the `stave transform` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "transform",
		Short: "Convert raw AWS CLI snapshots into obs.v0.1 observations (built-in jq)",
		Long: `Convert raw AWS CLI output into Stave's obs.v0.1 observation format.

Stave never calls AWS. You collect raw snapshots yourself (AWS CLI, Steampipe,
…); transform reshapes them in-process with embedded jq filters, scrubs
sensitive values (UserData, env var values, secret-keyed tags are hashed; policy
documents, ARNs, names, and actions are left intact), merges data spread across
several API calls into one asset, and validates the result against the obs.v0.1
schema before writing it.

Each raw file is matched to a filter by its top-level JSON key (e.g.
"Roles" -> iam-roles). Files no filter recognizes are skipped, not fatal. Run
with --coverage to list the recognized shapes.

Inputs:  --in, -i   directory of raw AWS CLI JSON files (default: raw)
         --account   AWS account ID for filters whose input carries no ARN
         --eval-time       captured_at timestamp (RFC3339); defaults to now
         --format, -f  summary format: text or json
Outputs: one obs.v0.1 file written to --out (or stdout with --out -); a summary
         on stdout (stderr when --out -).

Exit codes: 0 = success, 2 = input error (missing dir, bad JSON, bad flag),
            4 = internal error (e.g. transform produced an invalid observation),
            130 = interrupted.`,
		Example: `  # Convert a directory of raw snapshots into observations/
  stave transform -i raw/ -o observations/

  # Stream one observation document to stdout
  stave transform -i raw/ -o -

  # List the raw input shapes transform recognizes
  stave transform --coverage`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE:       func(cmd *cobra.Command, _ []string) error { return opts.Prepare(cmd) },
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}
	addFlags(cmd, opts)
	return cmd
}

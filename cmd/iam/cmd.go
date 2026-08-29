package iam

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the `stave iam` command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iam",
		Short: "IAM policy analysis commands",
		Long:  "Grouped IAM policy analysis commands: loop." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newLoopCmd())
	return cmd
}

func newLoopCmd() *cobra.Command {
	opts := &loopOptions{}
	cmd := &cobra.Command{
		Use:   "loop <policy.json>",
		Short: "Run one IAM policy analysis cycle",
		Long: `Loop runs one cycle of the IAM policy analysis pipeline: parse a policy
JSON file, generate a micro-observation (obs.v0.1), and render the
structural risk signals that the observation captured.

The composition spine connects iam-explain (parser, risk evaluator, SMT
exporter) to stave's evaluation engine via obs.v0.1 files. This command
runs one pass — no catalog verdicts, no diff, no watch.

Inputs:
  <policy.json>   IAM policy document (positional, required). Accepts a
                  full policy document, a bare Statement array, or a single
                  Statement object — iam-explain's parser handles all three.
  --format, -f    Output format: text (default), json

Outputs:
  stdout: micro-observation rendered as structured risk signals (text) or
          raw obs.v0.1 JSON (json)
  stderr: cycle wall-clock time

Exit codes:
  0   Cycle completed successfully
  2   Input error (missing policy, iam-explain not found)
  4   Internal error (parse failure, obs validation failure)
  130 Interrupted (SIGINT)

Requires: iam-explain binary in PATH (build from projects/iam-explain/).` + metadata.OfflineHelpSuffix,
		Example: `  # Analyze a dangerous policy
  stave iam loop examples/dangerous-policy.json

  # JSON output for piping
  stave iam loop --format json policy.json

  # From iam-explain's test fixtures
  stave iam loop projects/iam-explain/testdata/dangerous-policy.json`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			opts.PolicyPath = args[0]
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLoop(cmd, opts)
		},
	}
	addLoopFlags(cmd, opts)
	return cmd
}

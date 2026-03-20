package policy

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the inspect policy command.
func NewCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Analyze an S3 bucket policy document",
		Long: `Policy reads a raw S3 bucket policy JSON document and performs a
comprehensive security analysis including access assessment, prefix scope
analysis, risk scoring, and IAM action requirements.

Input: raw bucket policy JSON from --file or stdin.
Output: JSON report with assessment, prefix_scope, risk, and required_iam_actions.

Examples:
  stave inspect policy --file policy.json
  cat policy.json | stave inspect policy` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, file) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to policy JSON file (default: stdin)")

	return cmd
}

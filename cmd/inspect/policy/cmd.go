package policy

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the inspect policy command.
func NewCmd(resolver risk.PermissionResolver) *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Analyze an S3 bucket policy document",
		Long: `Policy reads a raw S3 bucket policy JSON document and performs a
comprehensive security analysis including access assessment, prefix scope
analysis, risk scoring, and IAM action requirements.

Inputs:
  --file, -f  Path to policy JSON file (default: stdin)

Outputs:
  stdout      JSON report with assessment, prefix_scope, risk, and required_iam_actions

Exit Codes:
  0   - Analysis completed successfully
  2   - Invalid input (malformed JSON, missing required fields)
  4   - Internal error
  130 - Interrupted (SIGINT)

` + metadata.OfflineHelpSuffix,
		Example: `  stave inspect policy --file policy.json
  cat policy.json | stave inspect policy
  stave inspect policy --file policy.json | jq .risk`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := fsutil.ReadFileOrStdin(file, cmd.InOrStdin())
			if err != nil {
				return err
			}
			report, err := Analyze(input, resolver)
			if err != nil {
				return err
			}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), report)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to policy JSON file (default: stdin)")

	return cmd
}

package risk

import (
	"github.com/spf13/cobra"

	domainrisk "github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// NewCmd constructs the inspect risk command.
func NewCmd(resolver domainrisk.PermissionResolver) *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Score risk from policy statement context",
		Long: `Risk reads a policy statement context and computes the risk score,
analyzing action permissions and principal exposure.

Input: JSON statement context from --file or stdin.
Output: JSON risk report with score, findings, and permissions.

Exit Codes:
  0    Success
  2    Input error
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave inspect risk --file statement.json
  cat statement.json | stave inspect risk`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			input, err := fsutil.ReadFileOrStdin(file, cmd.InOrStdin())
			if err != nil {
				return err
			}
			output, err := Analyze(input, resolver)
			if err != nil {
				return err
			}
			return jsonutil.WriteIndented(cmd.OutOrStdout(), output)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to risk input JSON file (default: stdin)")

	return cmd
}

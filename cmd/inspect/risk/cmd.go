package risk

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// NewCmd constructs the inspect risk command.
func NewCmd() *cobra.Command {
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
				return fmt.Errorf("read input: %w", err)
			}
			out, err := stave.InspectRisk(input)
			if err != nil {
				return err //nolint:wrapcheck // stave.InspectRisk already wraps with context ("parse risk input" / "encode risk report")
			}
			if _, err := cmd.OutOrStdout().Write(out); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to risk input JSON file (default: stdin)")

	return cmd
}

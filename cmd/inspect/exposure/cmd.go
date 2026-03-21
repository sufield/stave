package exposure

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the inspect exposure command.
func NewCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "exposure",
		Short: "Classify resource exposure vectors",
		Long: `Exposure reads normalized resource inputs and classifies their exposure
vectors, resolving bucket access, visibility, and trust boundaries.

Input: JSON object with resource exposure data from --file or stdin.
Output: JSON with classified exposures, visibility, and governance analysis.

Examples:
  stave inspect exposure --file resources.json
  cat resources.json | stave inspect exposure` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, file) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to exposure input JSON file (default: stdin)")

	return cmd
}

// Package aliases implements the inspect aliases command that lists
// predicate aliases and supported operators.
package aliases

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the inspect aliases command.
func NewCmd() *cobra.Command {
	var category string

	cmd := &cobra.Command{
		Use:   "aliases",
		Short: "List predicate aliases with metadata",
		Long: `Aliases lists all registered semantic predicate aliases with their
descriptions, categories, and supported operators. Optionally filter
by category.

Output: JSON array of alias info entries.

Exit Codes:
  0    Success
  4    Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave inspect aliases
  stave inspect aliases --category Encryption`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(Input{
				Stdout:   cmd.OutOrStdout(),
				Category: category,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&category, "category", "", "Filter by category (e.g. Encryption, Logging)")

	return cmd
}

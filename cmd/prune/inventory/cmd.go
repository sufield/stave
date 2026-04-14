// Package inventory implements the stave snapshot inventory subcommand
// for per-file snapshot intelligence consumed by external cleanup tools.
package inventory

import (
	"github.com/spf13/cobra"
)

// NewCmd creates the snapshot inventory command.
func NewCmd() *cobra.Command {
	opts := &inventoryOptions{
		RetentionDays: 90,
		Format:        "table",
		MinAssetCount: 10,
	}

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List snapshot files with cleanup recommendations",
		Long: `Emits a per-file inventory of snapshot files with the intelligence
an external cleanup tool needs: age, quality, assessment status, and
a recommended action (keep/archive/delete/review).

Stave provides the recommendation. The external tool executes the action.

Exit Codes:
  0   Inventory generated successfully
  2   Invalid input or directory not found
  4   Internal error

Examples:
  stave snapshot inventory --observations-dir ./observations/
  stave snapshot inventory --observations-dir ./obs/ --format json
  stave snapshot inventory --observations-dir ./obs/ --retention-days 30 --format openmetrics`,
		Example: `  stave snapshot inventory --observations-dir ./observations/
  stave snapshot inventory --observations-dir ./obs/ --format json --out inventory.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInventory(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.ObservationsDir, "observations-dir", "observations", "directory containing snapshot files")
	cmd.Flags().IntVar(&opts.RetentionDays, "retention-days", 90, "age threshold in days for retention eligibility")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | openmetrics")
	cmd.Flags().StringVar(&opts.Out, "out", "", "write to file instead of stdout")
	cmd.Flags().IntVar(&opts.MinAssetCount, "min-assets", 10, "minimum asset count for quality pass")

	return cmd
}

type inventoryOptions struct {
	ObservationsDir string
	RetentionDays   int
	Format          string
	Out             string
	MinAssetCount   int
}

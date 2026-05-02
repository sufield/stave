package snapshot

import (
	"github.com/spf13/cobra"
)

// NewQueryCmd constructs the `stave snapshot query` command. It
// inspects an observation directory and returns metadata about each
// snapshot file, or a health summary with --health.
func NewQueryCmd() *cobra.Command {
	opts := defaultQueryOptions()

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query snapshot archive metadata",
		Long: `Query inspects an observation directory and returns metadata about each
snapshot file including captured_at timestamp, age, size, and schema validity.

Use --health to produce a summary health report of the archive.

Exit Codes:
  0   Query completed
  2   Invalid input
  4   Internal error`,
		Example: `  stave snapshot query --dir observations
  stave snapshot query --dir observations --older-than 720h
  stave snapshot query --dir observations --health
  stave snapshot query --dir observations --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := runQuery(opts)
			if err != nil {
				return err
			}
			return renderQuery(cmd.OutOrStdout(), result, opts.Format)
		},
	}

	opts.BindFlags(cmd)
	return cmd
}

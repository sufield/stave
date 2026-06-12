package nep

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/pkg/stave"
)

type summaryOpts struct {
	Snapshot  string
	Format    string
	Threshold string
}

func newSummaryCmd() *cobra.Command {
	opts := &summaryOpts{Format: "table", Threshold: "elevated"}

	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Aggregate NEP metrics across all principals",
		Long: `Show a high-level NEP summary across all principals in the snapshot.
Includes privilege distribution, finding counts, chain metrics, and
highest-risk principals.

Exit Codes:
  0   No findings above threshold
  1   Critical findings exist
  2   High findings (no critical)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep summary --snapshot obs.json
  stave nep summary --snapshot obs.json --threshold critical --format json`,
		Example:       `  stave nep summary --snapshot obs.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.NepSummary(stave.NepSummaryConfig{
				Snapshot:  opts.Snapshot,
				Format:    opts.Format,
				Threshold: opts.Threshold,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write summary output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.Threshold, "threshold", "elevated", "severity threshold: none|limited|standard|elevated|admin")

	cliflags.MustMarkRequired(cmd, "snapshot")

	return cmd
}

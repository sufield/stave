package forge

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newPathsCmd() *cobra.Command {
	var snapshot, assetType, filter string

	cmd := &cobra.Command{
		Use:   "paths",
		Short: "List available observation property paths from a snapshot",
		Long: `Lists all observation property paths for a given asset type in a snapshot,
with types and presence counts. Map entries (like tags) are expanded to
show individual keys present in the snapshot.

Exit Codes:
  0   Paths listed successfully
  2   Invalid input or snapshot not found
  4   Internal error

Examples:
  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket
  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket --filter tags`,
		Example:       `  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ForgePaths(snapshot, assetType, filter)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write paths output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}

	cmd.Flags().StringVar(&snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "filter to a specific asset type")
	cmd.Flags().StringVar(&filter, "filter", "", "substring filter on path names")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

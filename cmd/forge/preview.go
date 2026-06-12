package forge

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func newPreviewCmd() *cobra.Command {
	var snapshot, predicateExpr, assetType, field, op, value string

	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Evaluate a predicate against a snapshot without writing files",
		Long: `Evaluates a control predicate against all matching assets in a snapshot
and shows per-resource FAIL/PASS results. Uses the identical CEL
evaluation path as stave apply.

Predicate can be specified as field/op/value or as a raw expression.

Exit Codes:
  0   Preview completed successfully
  2   Invalid input or missing flags
  4   Internal error

Examples:
  stave forge preview --snapshot obs.json \
    --field properties.storage.access.public_read --op eq --value true

  stave forge preview --snapshot obs.json --asset-type aws_s3_bucket \
    --field properties.storage.encryption.at_rest_enabled --op eq --value false`,
		Example:       `  stave forge preview --snapshot obs.json --field properties.storage.access.public_read --op eq --value true`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ForgePreview(snapshot, assetType, field, op, value, predicateExpr)
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil && err == nil {
				return fmt.Errorf("write preview output: %w", werr)
			}
			return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
		},
	}

	cmd.Flags().StringVar(&snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "filter to a specific asset type")
	cmd.Flags().StringVar(&field, "field", "", "predicate field path")
	cmd.Flags().StringVar(&op, "op", "eq", "predicate operator")
	cmd.Flags().StringVar(&value, "value", "true", "predicate value")
	cmd.Flags().StringVar(&predicateExpr, "predicate", "", "raw CEL predicate expression (alternative to field/op/value)")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

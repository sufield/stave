package diff

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the snapshot diff command.
func NewCmd() *cobra.Command {
	var (
		obsDir      string
		format      string
		changeTypes []string
		assetTypes  []string
		assetID     string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare the latest two observation snapshots",
		Long: `Diff compares the latest two snapshots in the observations directory and
reports asset-level changes (added, removed, modified) including property-level
differences for modified assets.

Examples:
  # Human-readable summary
  stave snapshot diff --observations ./observations

  # Machine-readable output
  stave snapshot diff --observations ./observations --format json

  # Write report to file
  stave snapshot diff --observations ./observations --format json > output/diff.json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			gf := cmdutil.GetGlobalFlags(cmd)
			runner := NewRunner(compose.ActiveProvider())
			return runner.Run(cmd.Context(), Config{
				ObservationsDir: obsDir,
				Format:          fmtValue,
				ChangeTypes:     changeTypes,
				AssetTypes:      assetTypes,
				AssetID:         assetID,
				Quiet:           gf.Quiet,
				Sanitizer:       gf.GetSanitizer(),
				Stdout:          cmd.OutOrStdout(),
				Stderr:          cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringSliceVar(&changeTypes, "change-type", nil, "Filter change types: added, removed, modified")
	cmd.Flags().StringSliceVar(&assetTypes, "asset-type", nil, "Filter asset type values")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "Filter by asset ID substring")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("change-type", cmdutil.CompleteFixed("added", "removed", "modified"))

	return cmd
}

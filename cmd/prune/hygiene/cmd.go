package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the hygiene command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var flags hygieneFlagsType

	cmd := &cobra.Command{
		Use:   "hygiene",
		Short: "Generate weekly lifecycle hygiene report in markdown",
		Long: `Hygiene generates a weekly markdown report for snapshot lifecycle operations:
snapshot inventory, retention posture, current violations, upcoming action items,
and trend vs last week.

Examples:
  # Print report to stdout
  stave snapshot hygiene --controls ./controls --observations ./observations

  # Write report to file for CI artifacts
  stave snapshot hygiene --controls ./controls --observations ./observations > output/weekly-hygiene.md

  # Deterministic weekly report
  stave snapshot hygiene --controls ./controls --observations ./observations --now 2026-01-20T00:00:00Z` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHygiene(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&flags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&flags.archiveDir, "archive-dir", "observations/archive", "Path to archived observation snapshots directory")
	cmd.Flags().StringVar(&flags.maxUnsafe, "max-unsafe", projconfig.Global().MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 168h, 7d)"))
	cmd.Flags().StringVar(&flags.dueSoon, "due-soon", "24h", "Threshold for due-soon upcoming actions")
	cmd.Flags().StringVar(&flags.lookback, "lookback", "7d", "Trend comparison window (e.g., 7d)")
	cmd.Flags().StringVar(&flags.olderThan, "older-than", projconfig.Global().SnapshotRetention(), cmdutil.WithDynamicDefaultHelp("Retention window used to estimate prune candidates"))
	cmd.Flags().StringVar(&flags.retentionTier, "retention-tier", projconfig.Global().RetentionTier(), cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	cmd.Flags().IntVar(&flags.keepMin, "keep-min", 2, "Minimum number of snapshots assumed for prune-candidate estimate")
	cmd.Flags().StringVar(&flags.now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringSliceVar(&flags.controlIDs, "control-id", nil, "Filter upcoming metrics to one or more control IDs")
	cmd.Flags().StringSliceVar(&flags.assetTypes, "asset-type", nil, "Filter upcoming metrics to one or more asset types")
	cmd.Flags().StringSliceVar(&flags.statuses, "status", nil, "Filter upcoming metrics by status: OVERDUE, DUE_NOW, UPCOMING")
	cmd.Flags().StringVar(&flags.dueWithin, "due-within", "", "Filter upcoming metrics to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))

	return cmd
}

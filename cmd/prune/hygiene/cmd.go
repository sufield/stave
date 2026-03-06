package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
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
	Args:          cobra.NoArgs,
	RunE:          runHygiene,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVarP(&hygieneFlags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	Cmd.Flags().StringVarP(&hygieneFlags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	Cmd.Flags().StringVar(&hygieneFlags.archiveDir, "archive-dir", "observations/archive", "Path to archived observation snapshots directory")
	Cmd.Flags().StringVar(&hygieneFlags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 168h, 7d)"))
	Cmd.Flags().StringVar(&hygieneFlags.dueSoon, "due-soon", "24h", "Threshold for due-soon upcoming actions")
	Cmd.Flags().StringVar(&hygieneFlags.lookback, "lookback", "7d", "Trend comparison window (e.g., 7d)")
	Cmd.Flags().StringVar(&hygieneFlags.olderThan, "older-than", cmdutil.ResolveSnapshotRetentionDefault(), cmdutil.WithDynamicDefaultHelp("Retention window used to estimate prune candidates"))
	Cmd.Flags().StringVar(&hygieneFlags.retentionTier, "retention-tier", cmdutil.ResolveRetentionTierDefault(), cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	Cmd.Flags().IntVar(&hygieneFlags.keepMin, "keep-min", 2, "Minimum number of snapshots assumed for prune-candidate estimate")
	Cmd.Flags().StringVar(&hygieneFlags.now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	Cmd.Flags().StringVarP(&hygieneFlags.format, "format", "f", "text", "Output format: text or json")
	Cmd.Flags().StringSliceVar(&hygieneFlags.controlIDs, "control-id", nil, "Filter upcoming metrics to one or more control IDs")
	Cmd.Flags().StringSliceVar(&hygieneFlags.resourceTypes, "resource-type", nil, "Filter upcoming metrics to one or more resource types")
	Cmd.Flags().StringSliceVar(&hygieneFlags.statuses, "status", nil, "Filter upcoming metrics by status: OVERDUE, DUE_NOW, UPCOMING")
	Cmd.Flags().StringVar(&hygieneFlags.dueWithin, "due-within", "", "Filter upcoming metrics to items due within duration from --now (e.g., 24h, 3d)")
	_ = Cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = Cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))
}

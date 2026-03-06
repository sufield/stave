package cleanup

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
	Use:   "prune",
	Short: "Prune stale observation snapshots by age",
	Long: `Prune removes old observation snapshots so the observations directory does not
grow indefinitely. Files are selected by snapshot captured_at age, not file mtime.

Safety defaults:
  - Keeps at least --keep-min snapshots (default: 2)
  - Defaults to dry-run when neither --dry-run nor --force is set
  - Actual deletion requires --force

Examples:
  # Preview snapshots older than 30 days
  stave snapshot prune --observations ./observations --older-than 30d --dry-run

  # Delete snapshots older than 30 days (keeping at least 2)
  stave snapshot prune --observations ./observations --older-than 30d --force

  # Deterministic retention window
  stave snapshot prune --observations ./observations --older-than 14d --now 2026-01-20T00:00:00Z --dry-run` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runDelete,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVarP(&deleteOpts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	Cmd.Flags().StringVar(&deleteOpts.OlderThan, "older-than", cmdutil.ResolveSnapshotRetentionDefault(), cmdutil.WithDynamicDefaultHelp("Prune snapshots older than this age (e.g., 14d, 720h)"))
	Cmd.Flags().StringVar(&deleteOpts.RetentionTier, "retention-tier", cmdutil.ResolveRetentionTierDefault(), cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	Cmd.Flags().StringVar(&deleteOpts.Now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	Cmd.Flags().IntVar(&deleteOpts.KeepMin, "keep-min", 2, "Minimum number of snapshots to keep")
	Cmd.Flags().BoolVar(&deleteOpts.DryRun, "dry-run", false, "Preview planned file operations without applying them")
	Cmd.Flags().StringVarP(&deleteOpts.Format, "format", "f", "text", "Output format: text or json")
	_ = Cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}

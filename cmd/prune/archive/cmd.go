package archive

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the archive command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var opts archiveOptions

	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Archive stale snapshots instead of deleting them",
		Long: `Archive moves old observation snapshots to an archive directory so teams keep
auditability while keeping daily observation directories fast.

Safety defaults:
  - Keeps at least --keep-min snapshots (default: 2)
  - Defaults to dry-run when neither --dry-run nor --force is set
  - Actual file moves require --force

Examples:
  # Preview snapshots older than 30 days
  stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 30d --dry-run

  # Move snapshots older than 30 days (keeping at least 2)
  stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 30d --force

  # Deterministic retention window
  stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 14d --now 2026-01-20T00:00:00Z --dry-run` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runArchive(cmd, &opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to active observation snapshots directory")
	cmd.Flags().StringVar(&opts.ArchiveDir, "archive-dir", "observations/archive", "Path to archive directory")
	cmd.Flags().StringVar(&opts.OlderThan, "older-than", cmdutil.ResolveSnapshotRetentionDefault(), cmdutil.WithDynamicDefaultHelp("Archive snapshots older than this age (e.g., 14d, 720h)"))
	cmd.Flags().StringVar(&opts.RetentionTier, "retention-tier", cmdutil.ResolveRetentionTierDefault(), cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	cmd.Flags().StringVar(&opts.Now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().IntVar(&opts.KeepMin, "keep-min", 2, "Minimum number of snapshots to keep in active observations")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Preview planned file operations without applying them")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

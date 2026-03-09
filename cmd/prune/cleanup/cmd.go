package cleanup

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the prune command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var opts deleteOptions

	cmd := &cobra.Command{
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
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDelete(cmd, &opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&opts.OlderThan, "older-than", projconfig.ResolveSnapshotRetentionDefault(), cmdutil.WithDynamicDefaultHelp("Prune snapshots older than this age (e.g., 14d, 720h)"))
	cmd.Flags().StringVar(&opts.RetentionTier, "retention-tier", projconfig.ResolveRetentionTierDefault(), cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	cmd.Flags().StringVar(&opts.Now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().IntVar(&opts.KeepMin, "keep-min", 2, "Minimum number of snapshots to keep")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Preview planned file operations without applying them")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

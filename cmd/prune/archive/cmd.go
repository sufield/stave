package archive

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the archive command.
func NewCmd() *cobra.Command {
	var (
		obsDir     string
		archiveDir string
		olderThan  string
		tier       string
		nowRaw     string
		keepMin    int
		dryRun     bool
		formatFlag string
	)

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
			gf := cmdutil.GetGlobalFlags(cmd)
			eval := projconfig.Global()

			if olderThan == "" {
				olderThan = eval.SnapshotRetention()
			}
			if tier == "" {
				tier = eval.RetentionTier()
			}

			validTier, err := pruneshared.ValidateRetentionTier(tier)
			if err != nil {
				return err
			}
			resolvedOlderThan, err := pruneshared.ResolveOlderThan(cmd, olderThan, validTier)
			if err != nil {
				return err
			}
			now, err := compose.ResolveNow(nowRaw)
			if err != nil {
				return err
			}
			format, err := compose.ResolveFormatValue(cmd, formatFlag)
			if err != nil {
				return err
			}

			cfg := Config{
				ObservationsDir: obsDir,
				ArchiveDir:      archiveDir,
				OlderThan:       resolvedOlderThan,
				RetentionTier:   validTier,
				Now:             now,
				KeepMin:         keepMin,
				DryRun:          dryRun,
				Force:           gf.Force,
				Quiet:           gf.Quiet,
				Format:          format,
				AllowSymlink:    gf.AllowSymlinkOut,
				Stdout:          cmd.OutOrStdout(),
			}

			runner := &Runner{}
			return runner.Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to active observation snapshots directory")
	f.StringVar(&archiveDir, "archive-dir", "observations/archive", "Path to archive directory")
	f.StringVar(&olderThan, "older-than", "", cmdutil.WithDynamicDefaultHelp("Archive snapshots older than this age (e.g., 14d, 720h)"))
	f.StringVar(&tier, "retention-tier", "", cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.IntVar(&keepMin, "keep-min", 2, "Minimum number of snapshots to keep in active observations")
	f.BoolVar(&dryRun, "dry-run", false, "Preview planned file operations without applying them")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// ResolveOlderThanForTest is exposed for test compatibility with pruneshared.
var ResolveOlderThanForTest = pruneshared.ResolveOlderThan

// ValidateRetentionTierForTest is exposed for test compatibility with pruneshared.
var ValidateRetentionTierForTest = pruneshared.ValidateRetentionTier

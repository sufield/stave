package archive

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the archive command.
func NewCmd(p *compose.Provider) *cobra.Command {
	opts := &options{
		ObsDir:     "observations",
		ArchiveDir: "observations/archive",
		KeepMin:    2,
		FormatFlag: "text",
	}

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
  stave snapshot archive --observations ./observations --archive-dir ./observations/archive --older-than 14d --now 2026-01-20T00:00:00Z --dry-run

Outputs:
  stdout        Summary: "Archived N snapshot(s) to <dir>" (or dry-run preview)
  stderr        Error messages (if any)

Exit Codes:
  0   - Archive completed successfully (or dry-run previewed)
  2   - Invalid input or configuration error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			ret, err := opts.resolveRetention(cmd)
			if err != nil {
				return err
			}

			runner := &runner{NewSnapshotRepo: p.NewSnapshotRepo}
			return runner.Run(cmd.Context(), config{
				ObservationsDir: opts.ObsDir,
				ArchiveDir:      opts.ArchiveDir,
				OlderThan:       ret.OlderThan,
				RetentionTier:   ret.RetentionTier,
				Now:             ret.Now,
				KeepMin:         opts.KeepMin,
				DryRun:          opts.DryRun,
				Force:           gf.Force,
				Quiet:           gf.Quiet,
				Format:          ret.Format,
				AllowSymlink:    gf.AllowSymlinkOut,
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

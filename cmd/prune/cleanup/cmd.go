package cleanup

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the prune command.
func NewCmd(p *compose.Provider) *cobra.Command {
	opts := &options{
		ObsDir:     "observations",
		KeepMin:    2,
		FormatFlag: "text",
	}

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune stale observation snapshots by age (dev-only)",
		Long: `Prune permanently deletes old observation snapshots. This command is available
only in stave-dev because observation snapshots are compliance evidence.
Use "stave snapshot archive" in production to move files without destroying them.

Files are selected by snapshot captured_at age, not file mtime.

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
  stave snapshot prune --observations ./observations --older-than 14d --now 2026-01-20T00:00:00Z --dry-run

Outputs:
  stdout        Summary: "Deleted N snapshot(s)" (or dry-run preview)
  stderr        Error messages and compliance warnings (if any)

Exit Codes:
  0   - Prune completed successfully (or dry-run previewed)
  2   - Invalid input or configuration error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			if gf.Force {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"WARNING: This operation permanently deletes observation snapshots.",
					"\nEnsure this complies with your data retention policies (HIPAA, SOX, PCI-DSS)",
					"before proceeding.")
			}

			ret, err := opts.resolveRetention(cmd)
			if err != nil {
				return err
			}

			runner := &runner{NewSnapshotRepo: p.NewSnapshotRepo}
			return runner.Run(cmd.Context(), config{
				ObservationsDir: opts.ObsDir,
				OlderThan:       ret.OlderThan,
				RetentionTier:   ret.RetentionTier,
				Now:             ret.Now,
				KeepMin:         opts.KeepMin,
				DryRun:          opts.DryRun,
				Force:           gf.Force,
				Quiet:           gf.Quiet,
				Format:          ret.Format,
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

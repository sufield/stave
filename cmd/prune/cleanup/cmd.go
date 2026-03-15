package cleanup

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the prune command.
func NewCmd() *cobra.Command {
	var (
		obsDir     string
		olderThan  string
		tier       string
		nowRaw     string
		keepMin    int
		dryRun     bool
		formatFlag string
	)

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
  stave snapshot prune --observations ./observations --older-than 14d --now 2026-01-20T00:00:00Z --dry-run` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			if gf.Force {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"WARNING: This operation permanently deletes observation snapshots.",
					"\nEnsure this complies with your data retention policies (HIPAA, SOX, PCI-DSS)",
					"before proceeding.")
			}
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
			resolvedOlderThan, err := pruneshared.ResolveOlderThan(olderThan, cmd.Flags().Changed("older-than"), validTier)
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

			runner := &Runner{}
			return runner.Run(cmd.Context(), Config{
				ObservationsDir: obsDir,
				OlderThan:       resolvedOlderThan,
				RetentionTier:   validTier,
				Now:             now,
				KeepMin:         keepMin,
				DryRun:          dryRun,
				Force:           gf.Force,
				Quiet:           gf.Quiet,
				Format:          format,
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&olderThan, "older-than", "", cmdutil.WithDynamicDefaultHelp("Prune snapshots older than this age (e.g., 14d, 720h)"))
	f.StringVar(&tier, "retention-tier", "", cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.IntVar(&keepMin, "keep-min", 2, "Minimum number of snapshots to keep")
	f.BoolVar(&dryRun, "dry-run", false, "Preview planned file operations without applying them")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

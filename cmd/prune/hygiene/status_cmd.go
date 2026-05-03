package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewStatusCmd constructs the snapshot status command (snapshot summary).
func NewStatusCmd(newObsRepo compose.ObsRepoFactory, newSnapshotRepo compose.SnapshotRepoFactory) *cobra.Command {
	opts := &rawOptions{}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show snapshot summary and retention posture",
		Long: `Status reports the physical health of the observation snapshot collection:
active count, archive count, purge candidates, and retention tier.

Inputs:
  --observations, -o    Path to observation snapshots directory
  --archive-dir         Path to archived snapshots
  --older-than          Retention window for prune-candidate estimate
  --retention-tier      Retention tier from stave.yaml
  --keep-min            Minimum snapshots for prune estimate
  --now                 Reference time (RFC3339)
  --format, -f          Output format: markdown or json

Exit Codes:
  0   - Status generated successfully
  2   - Invalid input
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example:       `  stave snapshot status --observations ./observations --now 2026-01-20T00:00:00Z`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.resolve(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			r := &runner{
				NewObsRepo:      newObsRepo,
				NewSnapshotRepo: newSnapshotRepo,
			}
			return r.RunStatus(compose.CommandContext(cmd), cfg)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&opts.arcDir, "archive-dir", "observations/archive", "Path to archived snapshots directory")
	f.StringVar(&opts.olderThan, "older-than", "", cliflags.WithDynamicDefaultHelp("Retention window for prune-candidate estimate"))
	f.StringVar(&opts.tier, "retention-tier", "", cliflags.WithDynamicDefaultHelp("Retention tier from stave.yaml"))
	f.IntVar(&opts.keepMin, "keep-min", 2, "Minimum snapshots for prune-candidate estimate")
	f.StringVar(&opts.nowRaw, "now", "", "Reference time (RFC3339)")
	f.StringVarP(&opts.formatFlag, "format", "f", "markdown", "Output format: markdown or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsMarkdownJSON...))

	// Defaults for fields used by shared resolve() but not needed by status.
	opts.dueSoon = "24h"
	opts.lookback = "7d"

	return cmd
}

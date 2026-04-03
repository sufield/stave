package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the hygiene command.
func NewCmd(loadAssets compose.AssetLoaderFunc, newObsRepo compose.ObsRepoFactory, newSnapshotRepo compose.SnapshotRepoFactory) *cobra.Command {
	opts := &rawOptions{}

	cmd := &cobra.Command{
		Use:   "hygiene",
		Short: "Generate weekly lifecycle hygiene report in markdown",
		Long: `Hygiene generates a weekly markdown report for snapshot lifecycle operations:
snapshot inventory, retention posture, current violations, upcoming action items,
and trend vs last week.

Inputs:
  --controls, -i        Path to control definitions directory (inferred if omitted)
  --observations, -o    Path to observation snapshots directory (default: observations)
  --archive-dir         Path to archived observation snapshots (default: observations/archive)
  --max-unsafe          Maximum allowed unsafe duration (from project config if omitted)
  --due-soon            Threshold for due-soon actions (default: 24h)
  --lookback            Trend comparison window (default: 7d)
  --older-than          Retention window for prune-candidate estimate (from config if omitted)
  --retention-tier      Retention tier from stave.yaml (from config if omitted)
  --keep-min            Minimum snapshots assumed for prune estimate (default: 2)
  --now                 Reference time (RFC3339). If omitted, uses wall clock
  --format, -f          Output format: markdown or json (default: markdown)
  --control-id          Filter upcoming metrics to specific control IDs (repeatable)
  --asset-type          Filter upcoming metrics to specific asset types (repeatable)
  --status              Filter upcoming by status: OVERDUE, DUE_NOW, UPCOMING (repeatable)
  --due-within          Filter upcoming to items due within duration from --now

Outputs:
  stdout                Weekly hygiene report (markdown or JSON)

Exit Codes:
  0   - Report generated successfully
  2   - Invalid input or configuration error
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  stave snapshot hygiene --controls ./controls --observations ./observations --now 2026-01-20T00:00:00Z`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.resolve(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			runner := &runner{
				LoadAssets:      loadAssets,
				NewObsRepo:      newObsRepo,
				NewSnapshotRepo: newSnapshotRepo,
			}
			return runner.Run(compose.CommandContext(cmd), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&opts.ctlDir, "controls", "i", "", "Path to control definitions directory")
	f.StringVarP(&opts.obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&opts.arcDir, "archive-dir", "observations/archive", "Path to archived observation snapshots directory")
	f.StringVar(&opts.maxUnsafe, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 168h, 7d)"))
	f.StringVar(&opts.dueSoon, "due-soon", "24h", "Threshold for due-soon upcoming actions")
	f.StringVar(&opts.lookback, "lookback", "7d", "Trend comparison window (e.g., 7d)")
	f.StringVar(&opts.olderThan, "older-than", "", cliflags.WithDynamicDefaultHelp("Retention window used to estimate prune candidates"))
	f.StringVar(&opts.tier, "retention-tier", "", cliflags.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.IntVar(&opts.keepMin, "keep-min", 2, "Minimum number of snapshots assumed for prune-candidate estimate")
	f.StringVar(&opts.nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&opts.formatFlag, "format", "f", "markdown", "Output format: markdown or json")
	f.StringSliceVar(&opts.controlIDs, "control-id", nil, "Filter upcoming metrics to one or more control IDs")
	f.StringSliceVar(&opts.assetTypes, "asset-type", nil, "Filter upcoming metrics to one or more asset types")
	f.StringSliceVar(&opts.statuses, "status", nil, "Filter upcoming metrics by status: OVERDUE, DUE_NOW, UPCOMING")
	f.StringVar(&opts.dueWithin, "due-within", "", "Filter upcoming metrics to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsMarkdownJSON...))
	_ = cmd.RegisterFlagCompletionFunc("status", cliflags.CompleteFixed(cliflags.AllThresholdStatuses()...))

	return cmd
}

package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the hygiene command.
func NewCmd(p *compose.Provider) *cobra.Command {
	opts := &rawOptions{}

	cmd := &cobra.Command{
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
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.resolve(cmd, cmdctx.EvaluatorFromCmd(cmd))
			if err != nil {
				return err
			}
			runner := &Runner{
				LoadAssets:      p.LoadAssets,
				NewObsRepo:      p.NewObservationRepo,
				NewSnapshotRepo: p.NewSnapshotRepo,
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
	f.StringVar(&opts.maxUnsafe, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 168h, 7d)"))
	f.StringVar(&opts.dueSoon, "due-soon", "24h", "Threshold for due-soon upcoming actions")
	f.StringVar(&opts.lookback, "lookback", "7d", "Trend comparison window (e.g., 7d)")
	f.StringVar(&opts.olderThan, "older-than", "", cmdutil.WithDynamicDefaultHelp("Retention window used to estimate prune candidates"))
	f.StringVar(&opts.tier, "retention-tier", "", cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.IntVar(&opts.keepMin, "keep-min", 2, "Minimum number of snapshots assumed for prune-candidate estimate")
	f.StringVar(&opts.nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&opts.formatFlag, "format", "f", "text", "Output format: text or json")
	f.StringSliceVar(&opts.controlIDs, "control-id", nil, "Filter upcoming metrics to one or more control IDs")
	f.StringSliceVar(&opts.assetTypes, "asset-type", nil, "Filter upcoming metrics to one or more asset types")
	f.StringSliceVar(&opts.statuses, "status", nil, "Filter upcoming metrics by status: OVERDUE, DUE_NOW, UPCOMING")
	f.StringVar(&opts.dueWithin, "due-within", "", "Filter upcoming metrics to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))

	return cmd
}

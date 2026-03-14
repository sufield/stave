package hygiene

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the hygiene command.
func NewCmd() *cobra.Command {
	var (
		ctlDir, obsDir, arcDir                        string
		maxUnsafe, dueSoon, lookback, olderThan, tier string
		keepMin                                       int
		nowRaw, formatFlag                            string
		controlIDs, assetTypes, statuses              []string
		dueWithin                                     string
	)

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
			gf := cmdutil.GetGlobalFlags(cmd)
			eval := projconfig.Global()

			// Path inference
			res, _ := projctx.NewResolver()
			engine := projctx.NewInferenceEngine(res)
			resolvedCtl := engine.InferDir("controls", ctlDir)
			resolvedObs := engine.InferDir("observations", obsDir)

			// Dynamic defaults
			if maxUnsafe == "" {
				maxUnsafe = eval.MaxUnsafe()
			}
			if olderThan == "" {
				olderThan = eval.SnapshotRetention()
			}
			if tier == "" {
				tier = eval.RetentionTier()
			}

			// Boundary parsing
			validTier, err := pruneshared.ValidateRetentionTier(tier)
			if err != nil {
				return err
			}
			retentionDur, err := pruneshared.ResolveOlderThan(olderThan, cmd.Flags().Changed("older-than"), validTier)
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
			maxUnsafeDur, err := timeutil.ParseDurationFlag(maxUnsafe, "--max-unsafe")
			if err != nil {
				return err
			}
			dueSoonDur, err := timeutil.ParseDurationFlag(dueSoon, "--due-soon")
			if err != nil {
				return err
			}
			lookbackDur, err := timeutil.ParseDurationFlag(lookback, "--lookback")
			if err != nil {
				return err
			}

			var withinDur = parseDueWithin(dueWithin)

			cfg := Config{
				ControlsDir:     fsutil.CleanUserPath(resolvedCtl),
				ObservationsDir: fsutil.CleanUserPath(resolvedObs),
				ArchiveDir:      fsutil.CleanUserPath(arcDir),
				MaxUnsafe:       maxUnsafeDur,
				DueSoon:         dueSoonDur,
				Lookback:        lookbackDur,
				OlderThan:       retentionDur,
				RetentionTier:   validTier,
				KeepMin:         keepMin,
				Now:             now,
				Format:          format,
				Quiet:           gf.Quiet,
				Stdout:          cmd.OutOrStdout(),
				Filter: UpcomingFilter{
					ControlIDs:   cmdutil.ToControlIDs(controlIDs),
					AssetTypes:   cmdutil.ToAssetTypes(assetTypes),
					Statuses:     toStatuses(statuses),
					DueWithin:    withinDur,
					DueWithinRaw: dueWithin,
				},
			}

			runner := &Runner{Provider: compose.ActiveProvider()}
			return runner.Run(compose.CommandContext(cmd), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&ctlDir, "controls", "i", "", "Path to control definitions directory")
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&arcDir, "archive-dir", "observations/archive", "Path to archived observation snapshots directory")
	f.StringVar(&maxUnsafe, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 168h, 7d)"))
	f.StringVar(&dueSoon, "due-soon", "24h", "Threshold for due-soon upcoming actions")
	f.StringVar(&lookback, "lookback", "7d", "Trend comparison window (e.g., 7d)")
	f.StringVar(&olderThan, "older-than", "", cmdutil.WithDynamicDefaultHelp("Retention window used to estimate prune candidates"))
	f.StringVar(&tier, "retention-tier", "", cmdutil.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.IntVar(&keepMin, "keep-min", 2, "Minimum number of snapshots assumed for prune-candidate estimate")
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	f.StringSliceVar(&controlIDs, "control-id", nil, "Filter upcoming metrics to one or more control IDs")
	f.StringSliceVar(&assetTypes, "asset-type", nil, "Filter upcoming metrics to one or more asset types")
	f.StringSliceVar(&statuses, "status", nil, "Filter upcoming metrics by status: OVERDUE, DUE_NOW, UPCOMING")
	f.StringVar(&dueWithin, "due-within", "", "Filter upcoming metrics to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))

	return cmd
}

func parseDueWithin(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, _ := timeutil.ParseDurationFlag(raw, "--due-within")
	return d
}

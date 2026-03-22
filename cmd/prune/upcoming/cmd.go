package upcoming

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the upcoming command.
func NewCmd(p *compose.Provider) *cobra.Command {
	var (
		ctlDir, obsDir             string
		maxUnsafe, dueSoon, nowRaw string
		formatFlag, dueWithin      string
		controlIDs, assetTypes     []string
		statuses                   []string
	)

	cmd := &cobra.Command{
		Use:   "upcoming",
		Short: "Generate upcoming snapshot action items for currently unsafe assets",
		Long: `Upcoming analyzes observations and controls to determine which currently-unsafe
assets need the next snapshot, and when. It outputs a table sorted
chronologically by due time so teams can prioritize upcoming actions.

Examples:
  # Print upcoming action table to stdout
  stave snapshot upcoming --controls ./controls --observations ./observations

  # Write markdown report file
  stave snapshot upcoming --controls ./controls --observations ./observations > upcoming.md

  # Deterministic planning with explicit now
  stave snapshot upcoming --controls ./controls --observations ./observations --now 2026-01-15T00:00:00Z` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			if !cmd.Flags().Changed("max-unsafe") {
				maxUnsafe = cmdctx.EvaluatorFromCmd(cmd).MaxUnsafeDuration()
			}

			cleanObsDir := fsutil.CleanUserPath(obsDir)
			cleanCtlDir := fsutil.CleanUserPath(ctlDir)

			cfg, err := gatherUpcomingConfig(upcomingConfigInput{
				MaxUnsafeRaw:  maxUnsafe,
				DueSoonRaw:    dueSoon,
				NowRaw:        nowRaw,
				FormatRaw:     formatFlag,
				DueWithinRaw:  dueWithin,
				ControlIDs:    convert.ToControlIDs(controlIDs),
				AssetTypes:    convert.ToAssetTypes(assetTypes),
				Statuses:      statuses,
				Sanitizer:     gf.GetSanitizer(),
				Quiet:         gf.Quiet,
				Stdout:        cmd.OutOrStdout(),
				ResolveFormat: func(raw string) (ui.OutputFormat, error) { return compose.ResolveFormatValue(cmd, raw) },
			})
			if err != nil {
				return err
			}

			// Load assets via Provider
			ctx := compose.CommandContext(cmd)
			loaded, err := p.LoadAssets(ctx, cleanObsDir, cleanCtlDir)
			if err != nil {
				return err
			}

			// Delegate to internal runner
			runner := &appupcoming.Runner{}
			output, err := runner.Run(
				appupcoming.EvalConfig{
					Controls:          loaded.Controls,
					Snapshots:         loaded.Snapshots,
					MaxUnsafeDuration: cfg.MaxUnsafeDuration,
					DueSoon:           cfg.DueSoon,
					Now:               cfg.Now,
					Filter:            cfg.Filter,
					Sanitizer:         cfg.Sanitizer,
					PredicateParser:   ctlyaml.ParsePredicate,
				},
				appupcoming.OutputMetadata{
					ControlsDir:          cleanCtlDir,
					ObservationsDir:      cleanObsDir,
					MaxUnsafeDurationRaw: cfg.MaxUnsafeDurationRaw,
					DueSoonRaw:           cfg.DueSoonRaw,
				},
			)
			if err != nil {
				return err
			}
			if cfg.Quiet {
				return nil
			}
			return renderOutput(cfg.Stdout, cfg.Format, output, cfg.DueSoon)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&ctlDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&maxUnsafe, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	f.StringVar(&nowRaw, "now", "", "Override current time (RFC3339). If omitted, uses wall clock")
	f.StringVar(&dueSoon, "due-soon", "24h", "Threshold for 'due soon' reminders (e.g., 4h, 1d)")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	f.StringSliceVar(&controlIDs, "control-id", nil, "Filter to one or more control IDs")
	f.StringSliceVar(&assetTypes, "asset-type", nil, "Filter to one or more asset types")
	f.StringSliceVar(&statuses, "status", nil, "Filter status: OVERDUE, DUE_NOW, UPCOMING")
	f.StringVar(&dueWithin, "due-within", "", "Filter to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))

	return cmd
}

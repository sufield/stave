package upcoming

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the upcoming command.
func NewCmd(p *compose.Provider) *cobra.Command {
	opts := &options{
		CtlDir:     "controls/s3",
		ObsDir:     "observations",
		DueSoon:    "24h",
		FormatFlag: "text",
	}

	cmd := &cobra.Command{
		Use:   "upcoming",
		Short: "Generate upcoming snapshot action items for currently unsafe assets",
		Long: `Upcoming analyzes observations and controls to determine which currently-unsafe
assets need the next snapshot, and when. It outputs a table sorted
chronologically by due time so teams can prioritize upcoming actions.

Inputs:
  --controls, -i      Path to control definitions directory (default: controls/s3)
  --observations, -o  Path to observation snapshots directory (default: observations)
  --max-unsafe        Maximum allowed unsafe duration (default: from project config)
  --now               Override current time (RFC3339). If omitted, uses wall clock
  --due-soon          Threshold for "due soon" reminders (default: 24h)
  --format, -f        Output format: text or json (default: text)
  --control-id        Filter to one or more control IDs (repeatable)
  --asset-type        Filter to one or more asset types (repeatable)
  --status            Filter status: OVERDUE, DUE_NOW, UPCOMING (repeatable)
  --due-within        Filter to items due within duration from --now

Outputs:
  stdout              Upcoming action table sorted by due time (text or JSON)
  stderr              Error messages (if any)

Exit Codes:
  0   - No upcoming violations found
  2   - Invalid input or configuration error
  3   - Upcoming violations exist
  130 - Interrupted (SIGINT)

Examples:
  # Print upcoming action table to stdout
  stave snapshot upcoming --controls ./controls --observations ./observations

  # Write markdown report file
  stave snapshot upcoming --controls ./controls --observations ./observations > upcoming.md

  # Deterministic planning with explicit now
  stave snapshot upcoming --controls ./controls --observations ./observations --now 2026-01-15T00:00:00Z` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)

			cfg, err := gatherUpcomingConfig(upcomingConfigInput{
				MaxUnsafeRaw:  opts.MaxUnsafe,
				DueSoonRaw:    opts.DueSoon,
				NowRaw:        opts.NowRaw,
				FormatRaw:     opts.FormatFlag,
				DueWithinRaw:  opts.DueWithin,
				ControlIDs:    convert.ToControlIDs(opts.ControlIDs),
				AssetTypes:    convert.ToAssetTypes(opts.AssetTypes),
				Statuses:      opts.Statuses,
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
			loaded, err := p.LoadAssets(ctx, opts.ObsDir, opts.CtlDir)
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
					ControlsDir:          opts.CtlDir,
					ObservationsDir:      opts.ObsDir,
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

	opts.BindFlags(cmd)

	return cmd
}

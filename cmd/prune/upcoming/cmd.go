package upcoming

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the upcoming command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var flags upcomingFlagsType

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
			return runUpcoming(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&flags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().StringVar(&flags.maxUnsafe, "max-unsafe", projconfig.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	cmd.Flags().StringVar(&flags.now, "now", "", "Override current time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().StringVar(&flags.dueSoon, "due-soon", "24h", "Threshold for 'due soon' reminders (e.g., 4h, 1d)")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringSliceVar(&flags.controlIDs, "control-id", nil, "Filter to one or more control IDs")
	cmd.Flags().StringSliceVar(&flags.assetTypes, "asset-type", nil, "Filter to one or more asset types")
	cmd.Flags().StringSliceVar(&flags.statuses, "status", nil, "Filter status: OVERDUE, DUE_NOW, UPCOMING")
	cmd.Flags().StringVar(&flags.dueWithin, "due-within", "", "Filter to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))

	return cmd
}

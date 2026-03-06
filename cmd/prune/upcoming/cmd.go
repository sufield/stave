package upcoming

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
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
	Args:          cobra.NoArgs,
	RunE:          runUpcoming,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVarP(&upcomingFlags.controlsDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	Cmd.Flags().StringVarP(&upcomingFlags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	Cmd.Flags().StringVar(&upcomingFlags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	Cmd.Flags().StringVar(&upcomingFlags.now, "now", "", "Override current time (RFC3339). If omitted, uses wall clock")
	Cmd.Flags().StringVar(&upcomingFlags.dueSoon, "due-soon", "24h", "Threshold for 'due soon' reminders (e.g., 4h, 1d)")
	Cmd.Flags().StringVarP(&upcomingFlags.format, "format", "f", "text", "Output format: text or json")
	Cmd.Flags().StringSliceVar(&upcomingFlags.controlIDs, "control-id", nil, "Filter to one or more control IDs")
	Cmd.Flags().StringSliceVar(&upcomingFlags.resourceTypes, "asset-type", nil, "Filter to one or more asset types")
	Cmd.Flags().StringSliceVar(&upcomingFlags.statuses, "status", nil, "Filter status: OVERDUE, DUE_NOW, UPCOMING")
	Cmd.Flags().StringVar(&upcomingFlags.dueWithin, "due-within", "", "Filter to items due within duration from --now (e.g., 24h, 3d)")
	_ = Cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = Cmd.RegisterFlagCompletionFunc("status", cmdutil.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))
}

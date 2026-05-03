package hygiene

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewRiskCmd constructs the snapshot risk command (SLA posture).
func NewRiskCmd(loadAssets compose.AssetLoaderFunc) *cobra.Command {
	opts := &rawOptions{}

	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Show SLA posture and remediation trends",
		Long: `Risk reports the logical health of the security posture: active findings,
SLA breaches, near-breach items, and trend vs previous audit window.

Inputs:
  --controls, -i        Path to control definitions directory
  --observations, -o    Path to observation snapshots directory
  --max-unsafe          Maximum allowed unsafe duration (SLA threshold)
  --due-soon            Threshold for near-breach items (default: 24h)
  --lookback            Trend comparison window (default: 7d)
  --now                 Reference time (RFC3339)
  --format, -f          Output format: markdown or json
  --control-id          Filter to specific control IDs (repeatable)
  --asset-type          Filter to specific asset types (repeatable)
  --status              Filter by status: OVERDUE, DUE_NOW, UPCOMING (repeatable)
  --due-within          Filter to items due within duration

Exit Codes:
  0   - Report generated successfully
  2   - Invalid input
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example:       `  stave snapshot risk --controls ./controls --observations ./observations --now 2026-01-20T00:00:00Z`,
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
			r := &runner{LoadAssets: loadAssets}
			return r.RunRisk(compose.CommandContext(cmd), cfg)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.ctlDir, "controls", "i", "", "Path to control definitions directory")
	f.StringVarP(&opts.obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&opts.maxUnsafe, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&opts.dueSoon, "due-soon", "24h", "Threshold for near-breach items")
	f.StringVar(&opts.lookback, "lookback", "7d", "Trend comparison window")
	f.StringVar(&opts.nowRaw, "now", "", "Reference time (RFC3339)")
	f.StringVarP(&opts.formatFlag, "format", "f", "markdown", "Output format: markdown or json")
	f.StringSliceVar(&opts.controlIDs, "control-id", nil, "Filter to specific control IDs (repeatable)")
	f.StringSliceVar(&opts.assetTypes, "asset-type", nil, "Filter to specific asset types (repeatable)")
	f.StringSliceVar(&opts.statuses, "status", nil, "Filter by status: OVERDUE, DUE_NOW, UPCOMING (repeatable)")
	f.StringVar(&opts.dueWithin, "due-within", "", "Filter to items due within duration from --now")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsMarkdownJSON...))
	_ = cmd.RegisterFlagCompletionFunc("status", cliflags.CompleteFixed(cliflags.AllThresholdStatuses()...))

	return cmd
}

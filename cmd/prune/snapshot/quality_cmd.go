package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

// NewQualityCmd constructs the quality command with closure-scoped flags.
func NewQualityCmd() *cobra.Command {
	var flags qualityFlagsType

	cmd := &cobra.Command{
		Use:   "quality",
		Short: "Check snapshot quality before evaluation",
		Long: `Quality checks the observation timeline for operational readiness before evaluation.
It can warn or fail on sparse timelines, stale snapshots, and missing key assets.

Examples:
  # Human-readable quality check
  stave snapshot quality --observations ./observations

  # Fail CI on warnings as well as errors
  stave snapshot quality --observations ./observations --strict

  # Require key resources to exist in latest snapshot
  stave snapshot quality --observations ./observations \
    --require-asset res:aws:s3:bucket:prod-audit \
    --require-asset res:aws:s3:bucket:prod-logs` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runQuality(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().IntVar(&flags.minSnapshots, "min-snapshots", 2, "Minimum expected number of snapshots")
	cmd.Flags().StringVar(&flags.maxStaleness, "max-staleness", "48h", "Maximum allowed age for latest snapshot (e.g., 24h, 2d)")
	cmd.Flags().StringVar(&flags.maxGap, "max-gap", "7d", "Maximum allowed gap between adjacent snapshots (e.g., 48h, 7d)")
	cmd.Flags().StringSliceVar(&flags.required, "require-asset", nil, "Asset ID required in latest snapshot (repeatable)")
	cmd.Flags().StringVar(&flags.now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&flags.strict, "strict", false, "Treat warnings as gate failures")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

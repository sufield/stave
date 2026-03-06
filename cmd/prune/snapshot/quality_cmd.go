package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

var Quality = &cobra.Command{
	Use:   "quality",
	Short: "Check snapshot quality before evaluation",
	Long: `Quality checks the observation timeline for operational readiness before evaluation.
It can warn or fail on sparse timelines, stale snapshots, and missing key resources.

Examples:
  # Human-readable quality check
  stave snapshot quality --observations ./observations

  # Fail CI on warnings as well as errors
  stave snapshot quality --observations ./observations --strict

  # Require key resources to exist in latest snapshot
  stave snapshot quality --observations ./observations \
    --require-resource res:aws:s3:bucket:prod-audit \
    --require-resource res:aws:s3:bucket:prod-logs` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runQuality,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Quality.Flags().StringVarP(&qualityFlags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	Quality.Flags().IntVar(&qualityFlags.minSnapshots, "min-snapshots", 2, "Minimum expected number of snapshots")
	Quality.Flags().StringVar(&qualityFlags.maxStaleness, "max-staleness", "48h", "Maximum allowed age for latest snapshot (e.g., 24h, 2d)")
	Quality.Flags().StringVar(&qualityFlags.maxGap, "max-gap", "7d", "Maximum allowed gap between adjacent snapshots (e.g., 48h, 7d)")
	Quality.Flags().StringSliceVar(&qualityFlags.required, "require-resource", nil, "Resource ID required in latest snapshot (repeatable)")
	Quality.Flags().StringVar(&qualityFlags.now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	Quality.Flags().StringVarP(&qualityFlags.format, "format", "f", "text", "Output format: text or json")
	Quality.Flags().BoolVar(&qualityFlags.strict, "strict", false, "Treat warnings as gate failures")
	_ = Quality.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}

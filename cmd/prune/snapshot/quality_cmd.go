package snapshot

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appsnapshot "github.com/sufield/stave/internal/app/prune/snapshot"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewQualityCmd constructs the quality command.
func NewQualityCmd(p *compose.Provider) *cobra.Command {
	var (
		obsDir       string
		minSnapshots int
		maxStaleness string
		maxGap       string
		required     []string
		nowRaw       string
		formatFlag   string
		strict       bool
	)

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
			gf := cmdutil.GetGlobalFlags(cmd)

			if minSnapshots < 1 {
				return fmt.Errorf("invalid --min-snapshots %d: must be >= 1", minSnapshots)
			}
			staleDur, err := timeutil.ParseDurationFlag(maxStaleness, "--max-staleness")
			if err != nil {
				return err
			}
			if staleDur < 0 {
				return fmt.Errorf("invalid --max-staleness %q: must be >= 0", maxStaleness)
			}
			gapDur, err := timeutil.ParseDurationFlag(maxGap, "--max-gap")
			if err != nil {
				return err
			}
			if gapDur < 0 {
				return fmt.Errorf("invalid --max-gap %q: must be >= 0", maxGap)
			}
			now, err := compose.ResolveNow(nowRaw)
			if err != nil {
				return err
			}
			format, err := compose.ResolveFormatValue(cmd, formatFlag)
			if err != nil {
				return err
			}

			// Load snapshots via Provider
			ctx := compose.CommandContext(cmd)
			cleanObsDir := fsutil.CleanUserPath(obsDir)
			snapshots, err := compose.LoadSnapshots(ctx, p, cleanObsDir)
			if err != nil {
				return fmt.Errorf("loading snapshots from %q: %w", cleanObsDir, err)
			}

			// Delegate to internal runner
			runner := appsnapshot.NewQualityRunner()
			return runner.Run(ctx, appsnapshot.QualityConfig{
				Snapshots:         snapshots,
				Now:               now,
				MinSnapshots:      minSnapshots,
				MaxStaleness:      staleDur,
				MaxGap:            gapDur,
				RequiredResources: required,
				Strict:            strict,
				Format:            format,
				Quiet:             gf.Quiet,
				Stdout:            cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.IntVar(&minSnapshots, "min-snapshots", 2, "Minimum expected number of snapshots")
	f.StringVar(&maxStaleness, "max-staleness", "48h", "Maximum allowed age for latest snapshot (e.g., 24h, 2d)")
	f.StringVar(&maxGap, "max-gap", "7d", "Maximum allowed gap between adjacent snapshots (e.g., 48h, 7d)")
	f.StringSliceVar(&required, "require-asset", nil, "Asset ID required in latest snapshot (repeatable)")
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	f.BoolVar(&strict, "strict", false, "Treat warnings as gate failures")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

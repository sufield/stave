package snapshot

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appsnapshot "github.com/sufield/stave/internal/app/prune/snapshot"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// qualityOptions holds the raw CLI flag values for the quality command.
type qualityOptions struct {
	ObsDir       string
	MinSnapshots int
	MaxStaleness string
	MaxGap       string
	Required     []string
	NowRaw       string
	FormatFlag   string
	Strict       bool
}

// Prepare validates flag values. Called from PreRunE.
func (o *qualityOptions) Prepare(_ *cobra.Command) error {
	if o.MinSnapshots < 1 {
		return &ui.UserError{Err: fmt.Errorf("invalid --min-snapshots %d: must be >= 1", o.MinSnapshots)}
	}
	staleDur, err := cliflags.ParseDurationFlag(o.MaxStaleness, "--max-staleness")
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if staleDur < 0 {
		return &ui.UserError{Err: fmt.Errorf("invalid --max-staleness %q: must be >= 0", o.MaxStaleness)}
	}
	gapDur, err := cliflags.ParseDurationFlag(o.MaxGap, "--max-gap")
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if gapDur < 0 {
		return &ui.UserError{Err: fmt.Errorf("invalid --max-gap %q: must be >= 0", o.MaxGap)}
	}
	return nil
}

// NewQualityCmd constructs the quality command.
func NewQualityCmd(loadSnapshots compose.SnapshotLoader) *cobra.Command {
	opts := &qualityOptions{
		ObsDir:       "observations",
		MinSnapshots: 2,
		MaxStaleness: "48h",
		MaxGap:       "7d",
		FormatFlag:   "text",
	}

	cmd := &cobra.Command{
		Use:   "quality",
		Short: "Check snapshot quality before evaluation",
		Long: `Quality checks the observation timeline for operational readiness before evaluation.
It can warn or fail on sparse timelines, stale snapshots, and missing key assets.

Inputs:
  --observations, -o  Path to observation snapshots directory (default: observations)
  --min-snapshots     Minimum expected number of snapshots (default: 2)
  --max-staleness     Maximum allowed age for latest snapshot (default: 48h)
  --max-gap           Maximum allowed gap between adjacent snapshots (default: 7d)
  --require-asset     Asset ID required in latest snapshot (repeatable)
  --now               Reference time (RFC3339). If omitted, uses wall clock
  --format, -f        Output format: text or json (default: text)
  --strict            Treat warnings as gate failures

Outputs:
  stdout              Quality check results (text or JSON)
  stderr              Error messages (if any)

Exit Codes:
  0   - All quality checks passed
  2   - Invalid input or configuration error
  3   - Quality check failures detected (or warnings with --strict)
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  stave snapshot quality --observations ./observations --strict`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)

			staleDur, _ := cliflags.ParseDurationFlag(opts.MaxStaleness, "--max-staleness")
			gapDur, _ := cliflags.ParseDurationFlag(opts.MaxGap, "--max-gap")
			now, err := compose.ResolveNow(opts.NowRaw)
			if err != nil {
				return err
			}
			format, err := compose.ResolveFormatValue(cmd, opts.FormatFlag)
			if err != nil {
				return err
			}

			ctx := compose.CommandContext(cmd)
			cleanObsDir := fsutil.CleanUserPath(opts.ObsDir)
			snapshots, err := loadSnapshots(ctx, cleanObsDir)
			if err != nil {
				return fmt.Errorf("loading snapshots from %q: %w", cleanObsDir, err)
			}

			runner := &appsnapshot.QualityRunner{}
			return runner.Run(appsnapshot.QualityConfig{
				Snapshots:         snapshots,
				Now:               now,
				MinSnapshots:      opts.MinSnapshots,
				MaxStaleness:      staleDur,
				MaxGap:            gapDur,
				RequiredResources: opts.Required,
				Strict:            opts.Strict,
				Format:            format,
				Quiet:             gf.Quiet,
				Stdout:            cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&opts.ObsDir, "observations", "o", opts.ObsDir, "Path to observation snapshots directory")
	f.IntVar(&opts.MinSnapshots, "min-snapshots", opts.MinSnapshots, "Minimum expected number of snapshots")
	f.StringVar(&opts.MaxStaleness, "max-staleness", opts.MaxStaleness, "Maximum allowed age for latest snapshot (e.g., 24h, 2d)")
	f.StringVar(&opts.MaxGap, "max-gap", opts.MaxGap, "Maximum allowed gap between adjacent snapshots (e.g., 48h, 7d)")
	f.StringSliceVar(&opts.Required, "require-asset", nil, "Asset ID required in latest snapshot (repeatable)")
	f.StringVar(&opts.NowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&opts.FormatFlag, "format", "f", opts.FormatFlag, "Output format: text or json")
	f.BoolVar(&opts.Strict, "strict", false, "Treat warnings as gate failures")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}

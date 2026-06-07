// Package readiness implements the 'stave readiness' command —
// a pre-evaluation report describing what Stave's catalog CAN'T
// detect against a given observation snapshot due to missing
// collector domains. Distinct from `stave apply --dry-run`,
// which checks input schema validity; readiness measures
// catalog effectiveness against the observed asset surface.
//
// The command is a thin shell over [stave.Readiness]: flag
// binding, one library call, output formatting. Step 2 of the
// migration plan in docs/architecture/pkg-stave-facade.md.
package readiness

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ObservationsDir string
	ControlsDir     string
	ChainsDir       string
	Format          string
	TopN            int
	Quiet           bool
	NoPager         bool
}

// NewCmd constructs the readiness command. Wired into the root
// in cmd/commands.go.
func NewCmd() *cobra.Command {
	opts := &options{
		Format:    "text",
		TopN:      5,
		ChainsDir: "chains",
	}

	cmd := &cobra.Command{
		Use:   "readiness",
		Short: "Report what Stave can/can't evaluate given the supplied observations",
		Long: `Readiness produces a pre-evaluation coverage report. It loads the
control catalog, the chain catalog, and the observation snapshots,
then reports — without running the evaluation engine — what
fraction of the catalog can fire against the observed asset surface.

Distinct from 'stave apply --dry-run', which checks input schema
validity (does it load? is the shape right?). Readiness measures
catalog effectiveness: of the ~2,600 controls and ~580 chains in
the catalog, how many can fire given what the collector captured?
Which asset types are absent? Which collection actions unlock the
most coverage?

Readiness is advisory. It does not gate 'stave apply' and it does
not run the engine. Operators can always evaluate what they have,
even if the snapshot exercises only a slice of the catalog.

Inputs:
  --observations DIR    Observation snapshot directory
  --controls DIR        Control catalog (default: embedded built-ins)
  --chains DIR          Chain catalog (default: chains)
  --format FORMAT       Output: text (default) | json
  --top N               Action plan entries (default: 5)

Outputs:
  stdout                The readiness report
  stderr                Loader diagnostics

Exit Codes:
  0   Report produced
  2   Input error
  4   Internal error
  130 SIGINT

Caveats:
  - Phase 1 measures asset-type coverage only. The intent
    dimension (data_classification tags, role-type labels,
    vendor_registry presence) and the foundational dimension
    (CloudTrail enabled, IMDSv2 enforced, GuardDuty baseline)
    are deferred pending catalog metadata.
  - Controls without applicable_asset_types declarations fall
    in the 'indeterminate' bucket. The analyzer cannot
    statically classify them; the engine fires them on any
    asset at evaluation time.`,
		Example: `  # Default text report against an observation directory
  stave readiness --observations ./my-snapshot

  # Machine-readable for CI or tooling
  stave readiness --observations ./my-snapshot --format json

  # Widen the action plan to the top 10 unblocking asset types
  stave readiness --observations ./my-snapshot --top 10`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := cmdutil.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := run(cmd.Context(), pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "", "observation snapshot directory (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().IntVar(&opts.TopN, "top", 5, "number of action-plan entries to surface")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "suppress output (exit code only)")

	_ = cmd.MarkFlagRequired("observations")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	renderer, err := NewRenderer(opts.Format)
	if err != nil {
		return err
	}

	report, err := stave.Readiness(ctx, stave.ReadinessOptions{
		SnapshotsDir: opts.ObservationsDir,
		ControlsDir:  opts.ControlsDir,
		ChainsDir:    opts.ChainsDir,
		TopN:         opts.TopN,
	})
	if err != nil {
		return fmt.Errorf("analyze readiness: %w", err)
	}

	if opts.Quiet {
		return nil
	}
	if err := renderer.Render(w, *report); err != nil {
		return fmt.Errorf("render readiness: %w", err)
	}
	return nil
}

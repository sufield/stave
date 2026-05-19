package readiness

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/app/readiness"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	ObservationsDir string
	ControlsDir     string
	ChainsDir       string
	Format          string
	TopN            int
	Quiet           bool
}

// NewCmd constructs the readiness command. Wired into the root
// in cmd/commands.go.
func NewCmd(deps Deps) *cobra.Command {
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
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}

	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "", "observation snapshot directory (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().IntVar(&opts.TopN, "top", 5, "number of action-plan entries to surface")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "suppress output (exit code only)")

	_ = cmd.MarkFlagRequired("observations")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return &ui.UserError{Err: rendErr}
	}

	snapshots, err := compose.LoadSnapshotsFrom(ctx, deps.NewObsRepo, opts.ObservationsDir)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}

	controls, err := compose.LoadControlsFrom(ctx, deps.NewCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	chains, err := compose.LoadChainDefinitions(ctx, deps.NewChainLoader, opts.ChainsDir)
	if err != nil {
		// Missing chains dir is not fatal — the analyzer can
		// still report on controls. Surface as a stderr note,
		// not a hard failure.
		if !isMissingChainsDir(err) {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}

	report := readiness.Analyze(controls, chains, snapshots, opts.TopN)

	if opts.Quiet {
		return nil
	}

	return renderer.Render(w, report)
}

// isMissingChainsDir returns true when the chain-loader failure
// is a "directory not present" condition. The loader treats this
// as valid (returns nil, nil from LoadChains), so this branch
// only fires for genuinely-wrapped not-found errors when the
// caller probed for a non-default path.
func isMissingChainsDir(err error) bool {
	if err == nil {
		return false
	}
	// The loader at internal/adapters/controls/yaml/chain_loader.go
	// already returns (nil, nil) when the directory is absent.
	// Anything that surfaces here is a different failure mode.
	var notFound interface{ NotFound() bool }
	return errors.As(err, &notFound) && notFound.NotFound()
}

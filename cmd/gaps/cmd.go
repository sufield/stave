// Package gaps implements the 'stave gaps' command — a
// field-level observation-gap report. For each (asset_type,
// property_path) the catalog declares, the command reports how
// many observed assets are missing that property, what controls
// and chains the absence blocks, and the priority order in which
// the operator should close them.
package gaps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appgaps "github.com/sufield/stave/internal/app/gaps"
	"github.com/sufield/stave/internal/cli/ui"
)

// Deps holds the adapter factories the gaps command needs. No
// CEL evaluator — gaps does not invoke the evaluation engine.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
	NewObsRepo     compose.ObsRepoFactory
}

type options struct {
	ObservationsDir string
	ControlsDir     string
	ChainsDir       string
	Format          string
	TopN            int
	Quiet           bool
}

// NewCmd constructs the gaps command. Wired into the root in
// cmd/commands.go.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		Format:    "text",
		TopN:      5,
		ChainsDir: "chains",
	}

	cmd := &cobra.Command{
		Use:   "gaps",
		Short: "Report which observation properties are absent + what they unlock",
		Long: `Gaps produces a field-level coverage report. For each
(asset_type, property_path) the catalog declares — i.e., paths
the predicate AST walker discovers from controls that carry
applicable_asset_types — it reports:

  - missing_count / total_count    how many observed assets of
                                   the type lack the property
  - controls_blocked               which controls would fire if
                                   the property were populated
  - chains_blocked                 chain count via member-control
                                   inheritance (deduplicated)
  - max_severity                   highest severity among readers
  - is_intent_property             tags + role-type label paths
                                   sort to the top of the plan
  - remediation.type               "tag" (seconds-per-asset) or
                                   "collector" (code change)
  - remediation.command            CLI template (tag) or doc
                                   pointer (collector)

Distinct from stave readiness, which reports asset-type-level
coverage ("did the collector emit any IAM roles at all?"). Gaps
goes one level deeper ("of the 22 buckets you emitted, 19 lack
data_classification, and that's blocking 98 chains").

Inputs:
  --observations DIR    Observation snapshot directory
  --controls DIR        Control catalog (default: controls)
  --chains DIR          Chain catalog (default: chains)
  --format FORMAT       Output: text (default) | json
  --top N               Action plan entries (default: 5)

Outputs:
  stdout                The gap report
  stderr                Loader diagnostics

Exit Codes:
  0   Report produced
  2   Input error
  4   Internal error
  130 SIGINT

Caveats:
  - Controls without applicable_asset_types declarations cannot
    surface gaps here. Their count appears in the summary so the
    operator knows the report is partial; run 'stave readiness'
    to see asset-type-level coverage.
  - Intent properties are currently a hardcoded canonical set
    (data_classification, role-type, environment for storage and
    compute). A future commit reads them from
    internal/controldata/taxonomy/intent_properties.yaml.
  - Per-asset-ID listings are not emitted by default. The
    aggregate counts ("19 of 22 buckets") are the scannable
    format; a future --verbose flag will expand them.

`,
		Example: `  # Top 5 field-level gaps against an observation directory
  stave gaps --observations ./my-snapshot

  # Machine-readable for CI or tooling
  stave gaps --observations ./my-snapshot --format json

  # Widen the surfaced gap list to the top 10 by unlock value
  stave gaps --observations ./my-snapshot --top 10`,
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
	cmd.Flags().IntVar(&opts.TopN, "top", 5, "number of top gaps to emphasise in the summary")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", false, "suppress output (exit code only)")

	_ = cmd.MarkFlagRequired("observations")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	switch opts.Format {
	case "text", "json":
		// ok
	default:
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
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
		// Missing chains dir is non-fatal: the analyzer still
		// reports control-level gaps.
		var notFound interface{ NotFound() bool }
		if !errors.As(err, &notFound) || !notFound.NotFound() {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}

	report := appgaps.Analyze(controls, chains, snapshots, opts.TopN)

	if opts.Quiet {
		return nil
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
	default:
		if err := writeText(w, report, opts.TopN); err != nil {
			return fmt.Errorf("render text: %w", err)
		}
	}
	return nil
}

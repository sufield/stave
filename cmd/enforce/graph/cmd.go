package graph

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

func NewCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Visualize control and asset relationships",
		Long:  "Grouped graph commands: coverage." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	graphCmd.AddCommand(newCoverageCmd(newCtlRepo, loadSnapshots))
	return graphCmd
}

func newCoverageCmd(newCtlRepo compose.CtlRepoFactory, loadSnapshots compose.SnapshotLoader) *cobra.Command {
	opts := &coverageOptions{
		ControlsDir: cliflags.DefaultControlsDir,
		ObsDir:      "observations",
		FormatRaw:   "dot",
	}

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show which controls cover which assets",
		Long: `Coverage outputs a graph showing control→asset edges.

Purpose: Visualize policy coverage — find uncovered assets, see control
scope, and understand protection density on high-value assets.

Uses the same matching logic as apply: for each control, tests its
unsafe_predicate against each asset from the latest observation snapshot.

Output Formats:
  --format dot    DOT graph (default) — pipe to graphviz for rendering
  --format json   Machine-readable JSON with edges and uncovered assets

Examples:
  # Output DOT graph to stdout
  stave graph coverage --controls ./controls --observations ./obs

  # Render as PNG (requires graphviz)
  stave graph coverage --controls ./controls --observations ./obs | dot -Tpng > coverage.png

  # JSON output with jq
  stave graph coverage --controls ./controls --observations ./obs --format json | jq .

  # Sanitize asset identifiers
  stave graph coverage --controls ./controls --observations ./obs --sanitize

Exit Codes:
  0   - Coverage graph generated successfully
  2   - Invalid input or configuration error
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  stave graph coverage --controls controls/s3 --observations observations`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := ParseFormat(opts.FormatRaw)
			if err != nil {
				return err
			}

			gf := cliflags.GetGlobalFlags(cmd)
			runner := newRunner(
				func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
					return compose.LoadControlsFrom(ctx, newCtlRepo, dir)
				},
				loadSnapshots,
			)

			return runner.Run(cmd.Context(), config{
				ControlsDir:     opts.ControlsDir,
				ObservationsDir: opts.ObsDir,
				Format:          format,
				AllowUnknown:    opts.AllowUnknown,
				Sanitizer:       gf.GetSanitizer(),
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("dot", "json"))

	return cmd
}

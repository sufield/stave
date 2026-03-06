package graph

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

func NewCmd() *cobra.Command {
	opts := defaultOptions()

	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Visualize control and asset relationships",
		Long:  "Grouped graph commands: coverage." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	coverageCmd := &cobra.Command{
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
  stave graph coverage --controls ./controls --observations ./obs --sanitize` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return runCoverage(cmd, opts) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.bindFlags(coverageCmd)
	graphCmd.AddCommand(coverageCmd)
	_ = coverageCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("dot", "json"))
	return graphCmd
}

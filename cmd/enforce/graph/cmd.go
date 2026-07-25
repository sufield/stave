package graph

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewCmd constructs the graph command group with its coverage and export
// subcommands.
func NewCmd() *cobra.Command {
	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Visualize control and asset relationships",
		Long:  "Grouped graph commands: coverage, export." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	graphCmd.AddCommand(newCoverageCmd())
	graphCmd.AddCommand(newExportCmd())
	graphCmd.AddCommand(newSilosCmd())
	return graphCmd
}

func newCoverageCmd() *cobra.Command {
	opts := defaultCoverageOptions()

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCoverage(cmd.Context(), opts, cliflags.GetGlobalFlags(cmd), cmd.OutOrStdout())
		},
		Annotations:   map[string]string{cmdutil.AnnotationSanitizeAware: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

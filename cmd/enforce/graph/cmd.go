package graph

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func NewCmd(p *compose.Provider) *cobra.Command {
	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Visualize control and asset relationships",
		Long:  "Grouped graph commands: coverage." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	graphCmd.AddCommand(newCoverageCmd(p))
	return graphCmd
}

func newCoverageCmd(p *compose.Provider) *cobra.Command {
	var (
		ctlDir       string
		obsDir       string
		formatRaw    string
		allowUnknown bool
	)

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
  stave graph coverage --controls ./controls --observations ./obs --sanitize` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := ParseFormat(formatRaw)
			if err != nil {
				return err
			}

			gf := cmdutil.GetGlobalFlags(cmd)
			runner := NewRunner(p)

			return runner.Run(cmd.Context(), Config{
				ControlsDir:     fsutil.CleanUserPath(ctlDir),
				ObservationsDir: fsutil.CleanUserPath(obsDir),
				Format:          format,
				AllowUnknown:    allowUnknown,
				Sanitizer:       gf.GetSanitizer(),
				Stdout:          cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&ctlDir, "controls", "i", "controls/s3", "Path to control definitions directory")
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVarP(&formatRaw, "format", "f", "dot", "Output format: dot or json")
	f.BoolVar(&allowUnknown, "allow-unknown-input", allowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))

	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("dot", "json"))

	return cmd
}

package graph

import (
	"github.com/spf13/cobra"
)

type chainsOptions struct {
	OutputFile string
	All        bool
}

func newChainsCmd() *cobra.Command {
	opts := &chainsOptions{}

	cmd := &cobra.Command{
		Use:   "chains",
		Short: "Visualize active attack path chains",
		Long: `Chains reads chain_findings from stave apply output and produces a
DOT graph showing active compound risk chains, their co-failing member
controls, and the attacker capability each chain produces.

Active chains are rendered as clusters with edges to a terminus node
representing the compound threat. Use --all to include inactive chains
as dotted clusters for context.

Output: DOT text to stdout — pipe to graphviz for rendering.

Exit Codes:
  0   - Graph generated successfully
  2   - Invalid input or missing output file
  4   - Internal error

Examples:
  stave graph chains --output ./output.json | dot -Tpng > chains.png

  stave apply --controls controls/ --observations obs/ \
    | stave graph chains --output - | dot -Tsvg > chains.svg

  stave graph chains --output ./output.json --all | dot -Tpng > all-chains.png`,
		Example: `  stave graph chains --output ./output.json | dot -Tpng > chains.png
  stave graph chains --output ./output.json --all`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runChains(chainsConfig{
				OutputFile: opts.OutputFile,
				All:        opts.All,
				Stdout:     cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to stave apply output file, or - for stdin (required)")
	cmd.Flags().BoolVar(&opts.All, "all", false, "include inactive chains as dotted clusters")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

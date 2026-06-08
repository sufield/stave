// Package path implements the 'stave path' command for attack path
// data export. Stave produces structured graph data (nodes and edges)
// from active chain findings — external tools perform graph analysis.
package path

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	AssessmentPath string
	ChainsDir      string
	Format         string
	OutFile        string
}

// NewCmd constructs the path command.
func NewCmd() *cobra.Command {
	opts := &options{
		ChainsDir: "chains",
		Format:    "json",
	}

	cmd := &cobra.Command{
		Use:   "path",
		Short: "Export attack path graph data from active chain findings",
		Long: `Produce a structured data export describing active chain findings,
directed edges between chains (postcondition of A satisfies
precondition of B), and control remediation actions per chain.

An external program performs path finding — BFS, DFS, shortest
path, centrality analysis, or any other graph algorithm. Stave
does not implement graph algorithms.

Inputs:
  --output PATH     Path to stave apply JSON output (required)
  --chains PATH     Path to chains directory (default: chains)
  --format STRING   Output format: json (default) | dot | csv-edges
  --out PATH        Write to file instead of stdout

Outputs:
  stdout            Attack path graph in selected format

Exit Codes:
  0   Graph produced
  2   Invalid input
  4   Internal error`,
		Example: `  # Produce graph data for external analysis
  stave path --output findings.json > attack-graph.json

  # Graphviz visualization
  stave path --output findings.json --format dot | dot -Tsvg > paths.svg

  # CSV edges for Python NetworkX
  stave path --output findings.json --format csv-edges > edges.csv`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPath(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.AssessmentPath, "output", "", "path to stave apply JSON output (required)")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "path to chains directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "output format: json | dot | csv-edges")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file instead of stdout")

	cliflags.MustMarkRequired(cmd, "output")

	return cmd
}

func runPath(stdout io.Writer, opts *options) error {
	data, err := fsutil.ReadFileLimited(opts.AssessmentPath)
	if err != nil {
		return fmt.Errorf("read assessment: %w", err)
	}

	out, err := stave.BuildAttackPath(data, opts.ChainsDir, opts.AssessmentPath, opts.Format, time.Now().UTC())
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped; all path errors are exit-4 plain.
	}
	if err := cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		_, werr := w.Write(out)
		return werr
	}); err != nil {
		return fmt.Errorf("write attack path: %w", err)
	}
	return nil
}

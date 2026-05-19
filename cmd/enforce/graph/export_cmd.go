package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	graphpkg "github.com/sufield/stave/internal/adapters/graph"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type exportOptions struct {
	OutputFile string
	OutPath    string
	Format     string
}

func newExportCmd() *cobra.Command {
	opts := &exportOptions{Format: "graph-json"}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export assessment as graph-json, STIX 2.1, JSON-LD, or GraphML",
		Long: `Export reads assessment JSON (from stave apply) and produces a
standards-based graph document. Every node and edge maps to
OCSF, STIX 2.1, ATT&CK, or OSCAL per docs/ontology/README.md.

Formats:
  graph-json   Stave graph-json (default)
  stix         STIX 2.1 Bundle JSON
  jsonld       JSON-LD against the Stave ontology — universal RDF
               format consumable by Neo4j GDS, igraph, NetworkX,
               Spark GraphX, Gephi, and any RDF-aware library.
  graphml      GraphML XML — native to igraph, NetworkX, Gephi,
               Cytoscape; carries node/edge attributes typed for
               graph data science (severity weights, partition
               labels).

Exit Codes:
  0   Export complete
  2   Input error`,
		Example: `  stave graph export --output assessment.json
  stave graph export --output assessment.json --format stix
  stave graph export --output assessment.json --format jsonld --out graph.jsonld
  stave graph export --output assessment.json --format graphml --out graph.graphml`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "Path to out.v0.1 assessment JSON")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "Write output to file instead of stdout")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "graph-json", "Output format: graph-json | stix | jsonld | graphml")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runExport(stdout io.Writer, opts *exportOptions) error {
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}

	var assessment report.Assessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", err)}
	}

	g := graphpkg.Build(graphpkg.BuildInput{
		Findings:      assessment.Findings,
		ChainFindings: assessment.ChainFindings,
		Now:           time.Now().UTC(),
		SourcePath:    opts.OutputFile,
	})

	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return rendErr
	}
	return cmdutil.WriteTo(stdout, opts.OutPath, func(out io.Writer) error {
		return renderer.Render(out, g)
	})
}

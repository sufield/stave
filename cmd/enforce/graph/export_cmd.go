package graph

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

type exportOptions struct {
	OutputFile string
	Format     string
}

func newExportCmd() *cobra.Command {
	opts := &exportOptions{Format: "json"}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export assessment as JSON, STIX 2.1, JSON-LD, or GraphML",
		Long: `Export reads assessment JSON (from stave apply) and produces a
standards-based graph document. Every node and edge maps to
OCSF, STIX 2.1, ATT&CK, or OSCAL per docs/ontology/README.md.

Formats:
  json         Native graph JSON (default)
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
  stave graph export --output assessment.json --format jsonld > graph.jsonld
  stave graph export --output assessment.json --format graphml > graph.graphml`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "Path to out.v0.1 assessment JSON")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "Output format: json | stix | jsonld | graphml")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runExport(stdout io.Writer, opts *exportOptions) error {
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}

	out, err := stave.ExportAssessmentGraph(data, opts.Format, opts.OutputFile, time.Now().UTC())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("render..."/"unsupported format"); preserve exit codes.
	}

	if _, writeErr := stdout.Write(out); writeErr != nil {
		return fmt.Errorf("write graph export: %w", writeErr)
	}
	return nil
}

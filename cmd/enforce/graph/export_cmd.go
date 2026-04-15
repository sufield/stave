package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
	graphpkg "github.com/sufield/stave/internal/graph"
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
		Short: "Export assessment as graph-json, STIX 2.1, or Neo4j Cypher",
		Long: `Export reads assessment JSON (from stave apply) and produces a
standards-based graph document. Every node and edge maps to
OCSF, STIX 2.1, ATT&CK, or OSCAL per docs/ontology/README.md.

Formats:
  graph-json     Stave graph-json (default)
  stix           STIX 2.1 Bundle JSON
  neo4j-cypher   Neo4j Cypher MERGE statements

Exit Codes:
  0   Export complete
  2   Input error`,
		Example: `  stave graph export --output assessment.json
  stave graph export --output assessment.json --format stix
  stave graph export --output assessment.json --format neo4j-cypher | cypher-shell`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "Path to out.v0.1 assessment JSON")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "Write output to file instead of stdout")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "graph-json", "Output format: graph-json | stix | neo4j-cypher")
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

	out := stdout
	if opts.OutPath != "" {
		f, createErr := os.Create(opts.OutPath)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "stix":
		return graphpkg.MarshalSTIX(out, g)
	case "neo4j-cypher":
		return graphpkg.MarshalCypher(out, g)
	default:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(g)
	}
}

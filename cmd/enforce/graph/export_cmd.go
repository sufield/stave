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
}

func newExportCmd() *cobra.Command {
	opts := &exportOptions{}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export assessment as graph-json for graph database import",
		Long: `Export reads assessment JSON (from stave apply) and produces a
standards-based graph-json document. Every node and edge maps to
OCSF, STIX 2.1, ATT&CK, or OSCAL per docs/ontology/README.md.

Inputs:
  --output PATH     Path to out.v0.1 assessment JSON (required)

Outputs:
  stdout or --out   Graph-json document

Exit Codes:
  0   Export complete
  2   Input error`,
		Example: `  stave graph export --output assessment.json
  stave graph export --output assessment.json --out graph.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "Path to out.v0.1 assessment JSON")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "Write graph-json to file instead of stdout")
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

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

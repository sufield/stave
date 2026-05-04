// Package path implements the 'stave path' command for attack path
// data export. Stave produces structured graph data (nodes and edges)
// from active chain findings — external tools perform graph analysis.
package path

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/attackpath"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
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

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

// assessmentJSON is the minimal subset of out.v0.1 we need.
type assessmentJSON struct {
	CompoundFindings []compoundFindingJSON `json:"compound_findings"`
	Findings         []findingJSON         `json:"findings"`
}

type compoundFindingJSON struct {
	Chain           string   `json:"chain"`
	ControlsFailing []string `json:"controls_failing"`
}

type findingJSON struct {
	ControlID   string `json:"control_id"`
	Remediation string `json:"remediation"`
}

func runPath(stdout io.Writer, opts *options) error {
	data, err := fsutil.ReadFileLimited(opts.AssessmentPath)
	if err != nil {
		return fmt.Errorf("read assessment: %w", err)
	}

	var assessment assessmentJSON
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return fmt.Errorf("parse assessment: %w", unmarshalErr)
	}

	chains, err := ctlyaml.LoadChains(opts.ChainsDir, capabilities.Builtin())
	if err != nil {
		return fmt.Errorf("load chains: %w", err)
	}

	// Build remediation lookup from assessment findings.
	remediationByCtl := make(map[string]string, len(assessment.Findings))
	for _, f := range assessment.Findings {
		if f.Remediation != "" {
			remediationByCtl[f.ControlID] = f.Remediation
		}
	}
	controlLookup := make(map[string]*policy.ControlDefinition)
	for cid, rem := range remediationByCtl {
		controlLookup[cid] = &policy.ControlDefinition{
			ID:          kernel.ControlID(cid),
			Remediation: policy.NewRemediationSpec("", rem, ""),
		}
	}

	var findings []attackpath.ActiveFinding
	for _, cf := range assessment.CompoundFindings {
		var cids []kernel.ControlID
		for _, c := range cf.ControlsFailing {
			cids = append(cids, kernel.ControlID(c))
		}
		findings = append(findings, attackpath.ActiveFinding{
			ChainID:         cf.Chain,
			ControlsFailing: cids,
		})
	}

	graph := attackpath.Build(attackpath.BuildInput{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		AssessmentPath: opts.AssessmentPath,
		Chains:         chains,
		Findings:       findings,
		ControlLookup:  controlLookup,
	})

	return cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		switch opts.Format {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(graph)
		case "dot":
			return attackpath.WriteDOT(w, graph)
		case "csv-edges":
			return attackpath.WriteCSVEdges(w, graph)
		default:
			return fmt.Errorf("unknown format %q (valid: json, dot, csv-edges)", opts.Format)
		}
	})
}

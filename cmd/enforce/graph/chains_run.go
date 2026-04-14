package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type chainsConfig struct {
	OutputFile string
	All        bool
	Stdout     io.Writer
}

// assessmentOutput is a minimal struct to extract chain_findings from
// stave apply output without importing the full report package.
type assessmentOutput struct {
	ChainFindings []risk.CompoundFinding `json:"chain_findings"`
}

// severityStyle holds DOT fill and border colors for a severity level.
type severityStyle struct {
	fill   string
	border string
}

var severityColors = map[string]severityStyle{
	"critical": {"#FCEBEB", "#E24B4A"},
	"high":     {"#FAEEDA", "#EF9F27"},
	"medium":   {"#E6F1FB", "#378ADD"},
	"low":      {"#F1EFE8", "#888780"},
	"info":     {"#F1EFE8", "#888780"},
}

func runChains(cfg chainsConfig) error {
	data, err := readInput(cfg.OutputFile)
	if err != nil {
		return err
	}

	var output assessmentOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid assessment output JSON: %w", err)}
	}

	var inactive []policy.ChainDefinition
	if cfg.All {
		inactive = loadInactiveChains(output.ChainFindings)
	}

	return writeDOTChains(cfg.Stdout, output.ChainFindings, inactive)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, &ui.UserError{Err: fmt.Errorf("read output file: %w", err)}
	}
	return data, nil
}

// loadInactiveChains loads chain definitions from the chains/ directory
// and returns those not present in the active findings.
func loadInactiveChains(active []risk.CompoundFinding) []policy.ChainDefinition {
	activeIDs := make(map[string]bool, len(active))
	for i := range active {
		activeIDs[active[i].ChainID] = true
	}

	chains, err := ctlyaml.LoadChains("chains")
	if err != nil {
		return nil // chains dir missing or unreadable — skip silently
	}

	var inactive []policy.ChainDefinition
	for _, c := range chains {
		if !activeIDs[c.ID] {
			inactive = append(inactive, c)
		}
	}
	return inactive
}

func writeDOTChains(w io.Writer, active []risk.CompoundFinding, inactive []policy.ChainDefinition) error {
	fmt.Fprintln(w, "digraph StaveChains {")
	fmt.Fprintln(w, `  rankdir="TB";`)
	fmt.Fprintln(w, `  node [shape=box, style=rounded];`)
	fmt.Fprintln(w)

	// Active chains
	for i := range active {
		f := &active[i]
		sev := strings.ToLower(f.Severity.String())
		style := severityColors[sev]
		if style.border == "" {
			style = severityStyle{"#F1EFE8", "#888780"}
		}
		slug := chainSlug(f.ChainID)

		// Cluster
		fmt.Fprintf(w, "  subgraph cluster_%s {\n", slug)
		fmt.Fprintf(w, "    label=%s;\n", dotQuote(f.ChainID+"\n"+strings.ToUpper(sev)))
		fmt.Fprintln(w, `    style="dashed";`)
		fmt.Fprintf(w, "    color=%s;\n", dotQuote(style.border))

		for _, ctl := range f.ControlsFailing {
			nodeID := slug + "::" + string(ctl)
			fmt.Fprintf(w, "    %s [label=%s, style=filled, fillcolor=%s];\n",
				dotQuote(nodeID),
				dotQuote(string(ctl)),
				dotQuote(style.fill))
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w)

		// Terminus node
		terminusID := "terminus_" + slug
		fmt.Fprintf(w, "  %s [label=%s, shape=diamond, style=filled, fillcolor=%s, color=%s];\n",
			dotQuote(terminusID),
			dotQuote(f.ChainID+"\nscore: "+fmt.Sprintf("%.0f", f.CompoundScore)),
			dotQuote(style.fill),
			dotQuote(style.border))
		fmt.Fprintln(w)

		// Edges
		for _, ctl := range f.ControlsFailing {
			nodeID := slug + "::" + string(ctl)
			fmt.Fprintf(w, "  %s -> %s;\n", dotQuote(nodeID), dotQuote(terminusID))
		}
		fmt.Fprintln(w)
	}

	// Inactive chains (--all mode)
	for i := range inactive {
		c := &inactive[i]
		slug := chainSlug(c.ID)

		fmt.Fprintf(w, "  subgraph cluster_%s {\n", slug)
		fmt.Fprintf(w, "    label=%s;\n", dotQuote(c.ID+"\n(inactive)"))
		fmt.Fprintln(w, `    style="dotted";`)
		fmt.Fprintf(w, "    color=%s;\n", dotQuote("#888780"))

		for _, ctl := range c.ControlIDs {
			nodeID := slug + "::" + string(ctl)
			fmt.Fprintf(w, "    %s [label=%s, style=filled, fillcolor=%s];\n",
				dotQuote(nodeID),
				dotQuote(string(ctl)),
				dotQuote("#F1EFE8"))
		}
		fmt.Fprintln(w, "  }")
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "}")
	return nil
}

func chainSlug(id string) string {
	s := strings.ReplaceAll(id, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

package attackpath

import (
	"fmt"
	"io"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// WriteDOT writes the graph in Graphviz DOT format.
func WriteDOT(w io.Writer, g *Graph) error {
	fmt.Fprintln(w, "digraph attack_paths {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, `  node [shape=box, style=filled];`)
	fmt.Fprintln(w)

	// Emit capability nodes.
	for _, cap := range g.Capabilities {
		color := capColor(string(cap.ID))
		fmt.Fprintf(w, "  %s [label=%q, fillcolor=%q, fontcolor=%q];\n",
			dotID(string(cap.ID)), cap.Label, color, fontColorFor(color))
	}
	fmt.Fprintln(w)

	// Emit edges: capability → capability via chain.
	for _, edge := range g.Edges {
		// Find the chain node to get severity.
		sev := ""
		for i := range g.ChainNodes {
			if g.ChainNodes[i].ChainID == edge.FromChain {
				sev = g.ChainNodes[i].Severity.String()
				break
			}
		}
		label := dotLabel(string(edge.FromChain)) + `\n[` + sev + `]`

		// Edge goes from precondition capabilities to postcondition capabilities
		// through the chain. For DOT simplicity, use via_capability as the link.
		for i := range g.ChainNodes {
			if g.ChainNodes[i].ChainID == edge.FromChain {
				for _, pre := range g.ChainNodes[i].Preconditions {
					fmt.Fprintf(w, "  %s -> %s [label=%q];\n",
						dotID(string(pre)), dotID(string(edge.ViaCapability)), label)
				}
				break
			}
		}
	}

	fmt.Fprintln(w, "}")
	return nil
}

// WriteCSVEdges writes edges as CSV.
func WriteCSVEdges(w io.Writer, g *Graph) error {
	fmt.Fprintln(w, "from_chain,to_chain,via_capability,from_severity,to_severity")

	sevMap := make(map[kernel.ChainID]policy.Severity, len(g.ChainNodes))
	for i := range g.ChainNodes {
		sevMap[g.ChainNodes[i].ChainID] = g.ChainNodes[i].Severity
	}

	for _, edge := range g.Edges {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s\n",
			edge.FromChain, edge.ToChain, edge.ViaCapability,
			sevMap[edge.FromChain].String(), sevMap[edge.ToChain].String())
	}
	return nil
}

func dotID(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

func dotLabel(s string) string {
	return strings.ReplaceAll(s, "_", " ")
}

func capColor(id string) string {
	switch {
	case strings.HasPrefix(id, "internet"):
		return "#ff4444"
	case strings.Contains(id, "credential") || strings.Contains(id, "root") || strings.Contains(id, "admin"):
		return "#ff8800"
	case strings.Contains(id, "data") || strings.Contains(id, "destruction"):
		return "#cc0000"
	case strings.Contains(id, "network"):
		return "#ffaa44"
	default:
		return "#ffcc44"
	}
}

func fontColorFor(bg string) string {
	switch bg {
	case "#ff4444", "#cc0000":
		return "white"
	default:
		return "black"
	}
}

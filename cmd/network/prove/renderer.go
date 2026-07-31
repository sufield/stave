package prove

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/network"
)

// Renderer is the format-dispatch interface for `stave network prove`.
type Renderer interface {
	Render(w io.Writer, r *network.ProofResult) error
}

// NewRenderer maps a format string to its Renderer.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return jsonRenderer{}, nil
	case "text", "":
		return textRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, text)", format)
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, r *network.ProofResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, r *network.ProofResult) error {
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	if r.Result == "UNSAT" {
		fmt.Fprintln(w, "Bastion SSH Routing Proof")
	} else {
		fmt.Fprintln(w, "Bastion SSH Routing Proof — BYPASS FOUND")
	}
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Production hosts: %d\n", r.ProductionHosts)
	fmt.Fprintf(w, "  Bastion hosts:    %d\n", r.BastionHosts)
	fmt.Fprintf(w, "  SSH paths:        %d\n", r.SSHPaths)
	fmt.Fprintln(w)

	if r.Result == "UNSAT" {
		fmt.Fprintln(w, "  PROOF: All SSH paths to production traverse a bastion host.")
		fmt.Fprintf(w, "  Solver: graph-search (completed in %dms)\n", r.SolveTimeMs)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  No bypass path exists.")
	} else {
		fmt.Fprintln(w, "  COUNTEREXAMPLE:")
		ce := r.Counterexample
		fmt.Fprintf(w, "    Source:      %s\n", ce.Source)
		fmt.Fprintf(w, "    Destination: %s\n", ce.Destination)
		fmt.Fprintf(w, "    Port:        %d\n", ce.Port)
		fmt.Fprintf(w, "    Path:        %s\n", ce.PathType)
		fmt.Fprintf(w, "    Rule SG:     %s\n", ce.RuleSG)
		fmt.Fprintf(w, "    Rule source: %s\n", ce.RuleSource)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", ce.Explanation)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  REMEDIATION:")
		fmt.Fprintf(w, "    %s\n", ce.Remediation)
	}
	return nil
}

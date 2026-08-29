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

var propertyTitles = map[string]string{
	"bastion-ssh":        "Bastion SSH Routing Proof",
	"prod-dev-isolation": "Production-Development Isolation Proof",
	"database-isolation": "Database Tier Isolation Proof",
	"firewall-mandatory": "Firewall Mandatory Routing Proof",
	"transitive-ssh":     "Transitive SSH Routing Proof",
	"transitive-egress":  "Transitive Internet Egress Proof",
}

func (textRenderer) Render(w io.Writer, r *network.ProofResult) error {
	title := propertyTitles[r.Property]
	if title == "" {
		title = r.Property
	}
	switch r.Result {
	case "SAT":
		title += " — VIOLATION FOUND"
	case "EVIDENCE_GATED":
		title += " — EVIDENCE GATED"
	}

	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w)

	// Bastion-specific scope fields.
	if r.ProductionHosts > 0 {
		fmt.Fprintf(w, "  Production hosts: %d\n", r.ProductionHosts)
	}
	if r.BastionHosts > 0 {
		fmt.Fprintf(w, "  Bastion hosts:    %d\n", r.BastionHosts)
	}
	if r.SSHPaths > 0 {
		fmt.Fprintf(w, "  SSH paths:        %d\n", r.SSHPaths)
	}
	// Generic scope fields.
	for k, v := range r.Scope {
		fmt.Fprintf(w, "  %s: %d\n", k, v)
	}
	fmt.Fprintln(w)

	switch r.Result {
	case "UNSAT":
		fmt.Fprintf(w, "  PROOF: %s\n", r.Interpretation)
		fmt.Fprintf(w, "  Solver: graph-search (completed in %dms)\n", r.SolveTimeMs)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  No violation exists.")
	case "EVIDENCE_GATED":
		ce := r.Counterexample
		fmt.Fprintln(w, "  EVIDENCE GATED:")
		fmt.Fprintf(w, "    Source:      %s\n", ce.Source)
		fmt.Fprintf(w, "    Destination: %s\n", ce.Destination)
		renderPort(w, ce)
		fmt.Fprintf(w, "    Path:        %s\n", ce.PathType)
		if ce.RuleSG != "" {
			fmt.Fprintf(w, "    Rule SG:     %s\n", ce.RuleSG)
		}
		if ce.RuleSource != "" {
			fmt.Fprintf(w, "    Rule source: %s\n", ce.RuleSource)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", ce.Explanation)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  REMEDIATION:")
		fmt.Fprintf(w, "    %s\n", ce.Remediation)
	default:
		ce := r.Counterexample
		fmt.Fprintln(w, "  COUNTEREXAMPLE:")
		fmt.Fprintf(w, "    Source:      %s\n", ce.Source)
		fmt.Fprintf(w, "    Destination: %s\n", ce.Destination)
		renderPort(w, ce)
		fmt.Fprintf(w, "    Path:        %s\n", ce.PathType)
		if ce.RuleSG != "" {
			fmt.Fprintf(w, "    Rule SG:     %s\n", ce.RuleSG)
		}
		if ce.RuleSource != "" {
			fmt.Fprintf(w, "    Rule source: %s\n", ce.RuleSource)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s\n", ce.Explanation)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  REMEDIATION:")
		fmt.Fprintf(w, "    %s\n", ce.Remediation)
	}
	return nil
}

func renderPort(w io.Writer, ce *network.Counterexample) {
	switch {
	case ce.Port > 0:
		fmt.Fprintf(w, "    Port:        %d\n", ce.Port)
	case ce.PathType != "direct-igw":
		fmt.Fprintf(w, "    Port:        all\n")
	}
}

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

func formatTitle(property, result string) string {
	title := propertyTitles[property]
	if title == "" {
		title = property
	}
	switch result {
	case "SAT":
		title += " — VIOLATION FOUND"
	case "EVIDENCE_GATED":
		title += " — EVIDENCE GATED"
	}
	return title
}

func renderHeader(w io.Writer, property, result string) {
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w, formatTitle(property, result))
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w)
}

func renderScope(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
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
}

func renderUnsat(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "  PROOF: %s\n", r.Interpretation)
	fmt.Fprintf(w, "  Solver: graph-search (completed in %dms)\n", r.SolveTimeMs)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  No violation exists.")
}

func (textRenderer) Render(w io.Writer, r *network.ProofResult) error {
	renderHeader(w, r.Property, r.Result)
	renderScope(w, r)

	switch r.Result {
	case "UNSAT":
		renderUnsat(w, r)
	case "EVIDENCE_GATED":
		renderCounterexample(w, "EVIDENCE GATED:", r.Counterexample)
	default:
		renderCounterexample(w, "COUNTEREXAMPLE:", r.Counterexample)
	}
	return nil
}

func renderCounterexample(w io.Writer, header string, ce *network.Counterexample) {
	if ce == nil {
		return
	}
	fmt.Fprintf(w, "  %s\n", header)
	fmt.Fprintf(w, "    Source:      %s\n", ce.Source)
	fmt.Fprintf(w, "    Destination: %s\n", ce.Destination)
	renderPort(w, ce)
	fmt.Fprintf(w, "    Path:        %s\n", ce.PathType)
	renderViolation(w, ce)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", ce.Explanation)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  REMEDIATION:")
	fmt.Fprintf(w, "    %s\n", ce.Remediation)
}

func renderViolation(w io.Writer, ce *network.Counterexample) {
	if ce.RoutePath != nil {
		fmt.Fprintf(w, "    Route table: %s\n", ce.RoutePath.RouteTableID)
		fmt.Fprintf(w, "    Destination: %s\n", ce.RoutePath.Destination)
		return
	}
	if ce.SGExposure != nil {
		if ce.SGExposure.SecurityGroupID != "" {
			fmt.Fprintf(w, "    Rule SG:     %s\n", ce.SGExposure.SecurityGroupID)
		}
		if ce.SGExposure.RuleSource != "" {
			fmt.Fprintf(w, "    Rule source: %s\n", ce.SGExposure.RuleSource)
		}
		return
	}
	if ce.RuleSG != "" {
		fmt.Fprintf(w, "    Rule SG:     %s\n", ce.RuleSG)
	}
	if ce.RuleSource != "" {
		fmt.Fprintf(w, "    Rule source: %s\n", ce.RuleSource)
	}
}

func renderPort(w io.Writer, ce *network.Counterexample) {
	switch {
	case ce.Port > 0:
		fmt.Fprintf(w, "    Port:        %d\n", ce.Port)
	case ce.PathType != "direct-igw":
		fmt.Fprintf(w, "    Port:        all\n")
	}
}

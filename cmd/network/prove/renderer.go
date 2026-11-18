package prove

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/network"
)

// ValidFormats contains the supported output format names.
var ValidFormats = []string{"json", "text"}

// IsValidFormat reports whether format is one of the supported output formats (or empty for default).
func IsValidFormat(format string) bool {
	return format == "" || slices.Contains(ValidFormats, format)
}

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
	return nil, fmt.Errorf("unknown format %q (valid: %s)", format, strings.Join(ValidFormats, ", "))
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

// PropertyTitle returns the human-readable display title for property.
func PropertyTitle(property string) string {
	if title, ok := propertyTitles[property]; ok {
		return title
	}
	return property
}

func formatTitle(property, result string) string {
	title := PropertyTitle(property)
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

func renderGenericScope(w io.Writer, scope map[string]int) {
	if len(scope) == 0 {
		return
	}
	keys := make([]string, 0, len(scope))
	for k := range scope {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "  %s: %d\n", k, scope[k])
	}
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
	if r.ScopeCount() > 0 {
		renderGenericScope(w, r.Scope)
	}
	fmt.Fprintln(w)
}

// FormatSolverCompletion returns the formatted solver completion line.
func FormatSolverCompletion(solveTimeMs int64) string {
	return fmt.Sprintf("Solver: graph-search (completed in %dms)", solveTimeMs)
}

func renderUnsat(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "  PROOF: %s\n", r.Interpretation)
	fmt.Fprintf(w, "  %s\n", FormatSolverCompletion(r.SolveTimeMs))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  No violation exists.")
}

func renderProofSummary(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	renderHeader(w, r.Property, r.Result)
	renderScope(w, r)
}

func verdictCounterexampleHeader(r *network.ProofResult) string {
	if r.IsEvidenceGated() {
		return "EVIDENCE GATED:"
	}
	return "COUNTEREXAMPLE:"
}

func renderVerdict(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	if r.IsUNSAT() {
		renderUnsat(w, r)
		return
	}
	renderCounterexample(w, verdictCounterexampleHeader(r), r.Counterexample)
}

func (textRenderer) Render(w io.Writer, r *network.ProofResult) error {
	if r == nil {
		return nil
	}
	renderProofSummary(w, r)
	renderVerdict(w, r)
	return nil
}

func renderCounterexample(w io.Writer, header string, ce *network.Counterexample) {
	if ce == nil {
		return
	}
	fmt.Fprintf(w, "  %s\n", header)
	renderCounterexamplePath(w, ce)
	renderRemediation(w, ce)
}

func renderCounterexamplePath(w io.Writer, ce *network.Counterexample) {
	if ce == nil {
		return
	}
	fmt.Fprintf(w, "    Source:      %s\n", ce.Source)
	fmt.Fprintf(w, "    Destination: %s\n", ce.Destination)
	renderPort(w, ce)
	fmt.Fprintf(w, "    Path:        %s\n", ce.PathType)
	renderViolation(w, ce)
	fmt.Fprintln(w)
}

func renderRemediation(w io.Writer, ce *network.Counterexample) {
	if ce == nil {
		return
	}
	fmt.Fprintf(w, "  %s\n", ce.Explanation)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  REMEDIATION:")
	fmt.Fprintf(w, "    %s\n", ce.Remediation)
}

func renderRouteViolation(w io.Writer, p *network.UnprotectedRoutePath) {
	if p == nil {
		return
	}
	fmt.Fprintf(w, "    Route table: %s\n", p.RouteTableID)
	fmt.Fprintf(w, "    Destination: %s\n", p.Destination)
}

func renderSGExposure(w io.Writer, ce *network.Counterexample) {
	if ce == nil {
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

func renderViolation(w io.Writer, ce *network.Counterexample) {
	if ce == nil {
		return
	}
	if ce.RoutePath != nil {
		renderRouteViolation(w, ce.RoutePath)
		return
	}
	renderSGExposure(w, ce)
}

func renderPort(w io.Writer, ce *network.Counterexample) {
	if ce == nil || ce.IsDirectIGW() {
		return
	}
	fmt.Fprintf(w, "    Port:        %s\n", network.FormatPort(ce.Port))
}

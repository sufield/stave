package prove

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
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
	network.PropertyBastionSSH:        "Bastion SSH Routing Proof",
	network.PropertyProdDevIsolation:  "Production-Development Isolation Proof",
	network.PropertyDatabaseIsolation: "Database Tier Isolation Proof",
	network.PropertyFirewallMandatory: "Firewall Mandatory Routing Proof",
	network.PropertyTransitiveSSH:     "Transitive SSH Routing Proof",
	network.PropertyTransitiveEgress:  "Transitive Internet Egress Proof",
}

// PropertyTitle returns the human-readable display title for property.
func PropertyTitle(property string) string {
	if title, ok := propertyTitles[property]; ok {
		return title
	}
	return property
}

// FormatTitle returns the formatted banner title combining the property name and result verdict.
// Safe on empty property.
func FormatTitle(property, result string) string {
	title := PropertyTitle(property)
	if title == "" {
		return ""
	}
	switch result {
	case network.VerdictSAT:
		title += " — VIOLATION FOUND"
	case network.VerdictEvidenceGated:
		title += " — EVIDENCE GATED"
	}
	return title
}

func renderHeader(w io.Writer, property, result string) {
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w, FormatTitle(property, result))
	fmt.Fprintln(w, "═══════════════════════════════════════════")
	fmt.Fprintln(w)
}

func sortedScopeKeys(scope map[string]int) []string {
	if len(scope) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(scope))
}

func renderGenericScope(w io.Writer, scope map[string]int) {
	for _, k := range sortedScopeKeys(scope) {
		fmt.Fprintf(w, "  %s: %d\n", k, scope[k])
	}
}

func renderBastionScope(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	if r.ProductionHosts > 0 {
		fmt.Fprintf(w, "  Production hosts: %d\n", r.ProductionHosts)
	}
	if r.BastionHosts > 0 {
		fmt.Fprintf(w, "  Bastion hosts:    %d\n", r.BastionHosts)
	}
	if r.SSHPaths > 0 {
		fmt.Fprintf(w, "  SSH paths:        %d\n", r.SSHPaths)
	}
}

func renderScope(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	// Bastion-specific scope fields.
	renderBastionScope(w, r)
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

// FormatUnsatProofBanner formats the proof interpretation line.
func FormatUnsatProofBanner(interpretation string) string {
	return "PROOF: " + interpretation
}

func renderUnsat(w io.Writer, r *network.ProofResult) {
	if r == nil {
		return
	}
	fmt.Fprintf(w, "  %s\n", FormatUnsatProofBanner(r.Interpretation))
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

// verdictCounterexampleHeader returns the section header string based on whether
// the proof result indicates evidence gating or a concrete counterexample.
// Returns empty string if r is nil.
func verdictCounterexampleHeader(r *network.ProofResult) string {
	if r == nil {
		return ""
	}
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
	ruleSG, ruleSource := ce.RuleSG, ce.RuleSource
	if ce.SGExposure != nil {
		ruleSG, ruleSource = ce.SGExposure.SecurityGroupID, ce.SGExposure.RuleSource
	}
	if ruleSG != "" {
		fmt.Fprintf(w, "    Rule SG:     %s\n", ruleSG)
	}
	if ruleSource != "" {
		fmt.Fprintf(w, "    Rule source: %s\n", ruleSource)
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

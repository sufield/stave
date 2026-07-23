// Package chainforge provides chain authoring, linting, and testing.
package chainforge

import (
	"fmt"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// LintResult holds chain lint output.
type LintResult struct {
	ChainID  string   `json:"chain_id"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// LintChain validates a chain definition against the control catalog
// and the catalog-supplied capability registry.
func LintChain(chain *policy.ChainDefinition, controlIDs map[kernel.ControlID]struct{}, registry policy.CapabilityRegistry) LintResult {
	result := LintResult{ChainID: string(chain.ID)}

	if chain.ID == "" {
		result.Errors = append(result.Errors, "missing required field: id")
	}
	if len(chain.ControlIDs) < 2 {
		result.Errors = append(result.Errors, "requires at least 2 member controls")
	}
	if chain.EscalationThreshold < 2 {
		result.Errors = append(result.Errors, "escalation_threshold must be >= 2 (a chain with threshold 1 is just a single-control finding)")
	}
	if chain.EscalationThreshold > len(chain.ControlIDs) {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"escalation_threshold (%d) > member count (%d)",
			chain.EscalationThreshold, len(chain.ControlIDs)))
	}

	// Check member controls exist in catalog.
	for _, cid := range chain.ControlIDs {
		if controlIDs != nil {
			if _, ok := controlIDs[cid]; !ok {
				result.Errors = append(result.Errors, fmt.Sprintf(
					"member control %q not found in catalog", cid))
			}
		}
	}

	// Validate capability strings against the catalog registry.
	if registry != nil {
		for _, cap := range chain.Preconditions {
			if !registry.IsValid(cap) {
				result.Errors = append(result.Errors, fmt.Sprintf(
					"precondition %q is not a valid capability", cap))
			}
		}
		for _, cap := range chain.Postconditions {
			if !registry.IsValid(cap) {
				result.Errors = append(result.Errors, fmt.Sprintf(
					"postcondition %q is not a valid capability", cap))
			}
		}
	}

	// Validate implicit dependencies.
	for i, dep := range chain.ImplicitDependencies {
		prefix := fmt.Sprintf("implicit_dependencies[%d]", i)
		if dep.Source == "" {
			result.Errors = append(result.Errors, prefix+": source is required")
		}
		switch dep.Fallback {
		case policy.FallbackFailClosed, policy.FallbackCrossValidate:
			if dep.Diagnostic == "" {
				result.Errors = append(result.Errors, fmt.Sprintf(
					"%s: diagnostic is required when fallback is %q", prefix, dep.Fallback))
			}
		case policy.FallbackFailOpen:
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"%s: fallback is fail_open (source %q) — verify this is intentional", prefix, dep.Source))
		default:
			result.Errors = append(result.Errors, fmt.Sprintf(
				"%s: invalid fallback %q (must be fail_closed, fail_open, or cross_validate)", prefix, dep.Fallback))
		}
	}

	// Warnings.
	if len(chain.Preconditions) == 0 {
		result.Warnings = append(result.Warnings, "no preconditions defined (chain will not produce attack path edges)")
	}
	if len(chain.Postconditions) == 0 {
		result.Warnings = append(result.Warnings, "no postconditions defined")
	}
	if chain.Description == "" {
		result.Warnings = append(result.Warnings, "missing description/narrative")
	}

	return result
}

// LintChainRaw wraps LintChain and adds a raw-bytes check for the
// implicit_dependencies field. The parsed struct can't distinguish
// "field absent" from "field present but empty" (both are nil),
// so the field-presence check operates on raw YAML bytes.
func LintChainRaw(raw []byte, chain *policy.ChainDefinition, controlIDs map[kernel.ControlID]struct{}, registry policy.CapabilityRegistry) LintResult {
	result := LintChain(chain, controlIDs, registry)
	if !strings.Contains(string(raw), "implicit_dependencies") {
		result.Errors = append(result.Errors, "missing required field: implicit_dependencies (declare [] if none)")
	}
	return result
}

// FormatLint produces human-readable lint output.
func FormatLint(r LintResult) string {
	var b strings.Builder
	b.WriteString(r.ChainID)
	b.WriteByte('\n')
	for _, e := range r.Errors {
		b.WriteString("  ERROR   ")
		b.WriteString(e)
		b.WriteByte('\n')
	}
	for _, w := range r.Warnings {
		b.WriteString("  WARNING ")
		b.WriteString(w)
		b.WriteByte('\n')
	}
	return b.String()
}

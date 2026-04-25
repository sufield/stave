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
func LintChain(chain *policy.ChainDefinition, controlIDs map[kernel.ControlID]bool, registry policy.CapabilityRegistry) LintResult {
	result := LintResult{ChainID: chain.ID}

	if chain.ID == "" {
		result.Errors = append(result.Errors, "missing required field: id")
	}
	if len(chain.ControlIDs) < 2 {
		result.Errors = append(result.Errors, "requires at least 2 member controls")
	}
	if chain.EscalationThreshold < 1 {
		result.Errors = append(result.Errors, "escalation_threshold must be >= 1")
	}
	if chain.EscalationThreshold > len(chain.ControlIDs) {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"escalation_threshold (%d) > member count (%d)",
			chain.EscalationThreshold, len(chain.ControlIDs)))
	}

	// Check member controls exist in catalog.
	for _, cid := range chain.ControlIDs {
		if controlIDs != nil && !controlIDs[cid] {
			result.Errors = append(result.Errors, fmt.Sprintf(
				"member control %q not found in catalog", cid))
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

// FormatLint produces human-readable lint output.
func FormatLint(r LintResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.ChainID)
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "  ERROR   %s\n", e)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  WARNING %s\n", w)
	}
	return b.String()
}

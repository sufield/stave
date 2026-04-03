// Package compound detects dangerous combinations of control results
// that represent higher risk than any individual finding alone.
// Compound risks are evaluated after individual controls and prepended
// to the profile report.
package compound

import (
	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// CompoundFinding represents a risk that emerges from the combination
// of multiple invariant results.
type CompoundFinding struct {
	// ID uniquely identifies this compound risk (e.g. "COMPOUND.001").
	ID string `json:"id"`

	// Severity is the impact level of the combined risk.
	Severity policy.Severity `json:"severity"`

	// TriggerIDs lists the invariant IDs whose results triggered this finding.
	TriggerIDs []string `json:"trigger_ids"`

	// Message describes the combined risk in practitioner language.
	Message string `json:"message"`
}

// CompoundRule defines a single compound risk detection pattern.
type CompoundRule struct {
	// ID uniquely identifies this rule.
	ID string

	// Severity is the finding severity when the rule matches.
	Severity policy.Severity

	// TriggerIDs lists the invariant IDs this rule examines.
	TriggerIDs []string

	// Message is the finding message when the rule matches.
	Message string

	// Matches returns true when the result set triggers this compound risk.
	Matches func(results []compliance.Result) bool
}

// Detect runs all rules against the result set and returns any compound findings.
// It is a pure function: no I/O, no global state.
func Detect(rules []CompoundRule, results []compliance.Result) []CompoundFinding {
	var findings []CompoundFinding
	for _, rule := range rules {
		if rule.Matches(results) {
			findings = append(findings, CompoundFinding{
				ID:         rule.ID,
				Severity:   rule.Severity,
				TriggerIDs: rule.TriggerIDs,
				Message:    rule.Message,
			})
		}
	}
	return findings
}

// --- Result lookup helpers ---

// resultFailed returns true if the given invariant ID has a failing result.
func resultFailed(results []compliance.Result, id string) bool {
	for _, r := range results {
		if r.ControlID == id {
			return !r.Pass
		}
	}
	return false
}

// resultPassed returns true if the given invariant ID has a passing result.
func resultPassed(results []compliance.Result, id string) bool {
	for _, r := range results {
		if r.ControlID == id {
			return r.Pass
		}
	}
	return false
}

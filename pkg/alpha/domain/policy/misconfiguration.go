package policy

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

// propertiesPathPrefix is the internal namespace for asset-specific data.
const propertiesPathPrefix = "properties."

// Misconfiguration describes a specific property-level condition that triggered
// a security violation. It provides the "Logic Proof" for the finding.
type Misconfiguration struct {
	// Property is the raw field path (e.g., "properties.public_access_block.block_public_acls").
	Property string `json:"property"`

	// ActualValue is the state observed on the resource during evaluation.
	ActualValue any `json:"actual_value"`

	// Operator is the logic gate that failed (e.g., "eq", "missing", "contains").
	Operator predicate.Operator `json:"operator"`

	// UnsafeValue is the value or threshold defined in the policy that triggered the violation.
	UnsafeValue any `json:"unsafe_value,omitempty"`
}

// DisplayProperty returns the property path without the internal "properties." prefix.
func (m Misconfiguration) DisplayProperty() string {
	return strings.TrimPrefix(m.Property, propertiesPathPrefix)
}

// IsMissing reports whether the violation was caused by a required property being absent.
func (m Misconfiguration) IsMissing() bool {
	return m.Operator == predicate.OpMissing || m.ActualValue == nil
}

// Sanitized returns a copy of the misconfiguration with the actual value redacted.
// Use this before including evidence in public or shared reports.
func (m Misconfiguration) Sanitized() Misconfiguration {
	m.ActualValue = kernel.Redacted
	return m
}

// String returns a human-readable explanation of why this property is considered misconfigured.
func (m Misconfiguration) String() string {
	path := m.DisplayProperty()

	if m.IsMissing() {
		return fmt.Sprintf("property %q is missing", path)
	}

	switch m.Operator {
	case predicate.OpEq:
		return fmt.Sprintf("property %q has unsafe value: %v", path, m.ActualValue)

	case predicate.OpContains:
		return fmt.Sprintf("property %q contains unsafe element: %v", path, m.ActualValue)

	case predicate.OpAnyMatch:
		return fmt.Sprintf("one or more items in %q matched unsafe criteria", path)

	default:
		// Fallback for custom or less common operators
		return fmt.Sprintf("property %q (value: %v) failed %s check against %v",
			path, m.ActualValue, m.Operator, m.UnsafeValue)
	}
}

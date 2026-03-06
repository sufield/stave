package policy

import (
	"fmt"
	"strings"
)

const fieldNamespacePropertiesPrefix = "properties."

// PredicateOperator identifies a predicate comparison operator (eq, ne, missing, etc.).
type PredicateOperator string

// Misconfiguration represents a single property-level unsafe condition detected
// by an control's predicate. It captures what was found and why it is unsafe.
type Misconfiguration struct {
	// Property is the field path that triggered the match.
	Property string `json:"property"`
	// ActualValue is the observed value of the property (nil if missing).
	ActualValue any `json:"actual_value"`
	// Operator is the predicate operator that matched: eq, ne, missing, etc.
	Operator PredicateOperator `json:"operator"`
	// UnsafeValue is the threshold or comparison value from the predicate clause.
	UnsafeValue any `json:"unsafe_value,omitempty"`
}

// DisplayProperty returns a cleaner property path for human-facing output.
func (m Misconfiguration) DisplayProperty() string {
	return strings.TrimPrefix(m.Property, fieldNamespacePropertiesPrefix)
}

// IsMissing reports whether this violation indicates a missing field.
func (m Misconfiguration) IsMissing() bool {
	return m.Operator == "missing" || m.ActualValue == nil
}

// Sanitized returns a copy with sensitive observed values removed.
func (m Misconfiguration) Sanitized() Misconfiguration {
	out := m
	out.ActualValue = "[SANITIZED]"
	return out
}

// String returns a normalized, human-readable reason string.
func (m Misconfiguration) String() string {
	prop := m.DisplayProperty()
	if m.IsMissing() {
		return fmt.Sprintf("property '%s' is missing", prop)
	}

	switch m.Operator {
	case "eq", "equals":
		return fmt.Sprintf("property '%s' is exactly '%v'", prop, m.ActualValue)
	case "contains":
		return fmt.Sprintf("property '%s' contains unsafe value '%v'", prop, m.ActualValue)
	case "any_match":
		return fmt.Sprintf("one or more items in '%s' matched the unsafe criteria", prop)
	default:
		return fmt.Sprintf(
			"property '%s' (%v) failed '%s' check against '%v'",
			prop, m.ActualValue, m.Operator, m.UnsafeValue,
		)
	}
}

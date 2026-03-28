package controldef

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// propertiesPathPrefix is the internal namespace for asset-specific data.
const propertiesPathPrefix = "properties."

// Category identifies the architectural layer of a security violation.
type Category int

const (
	CategoryUnknown Category = iota
	// CategoryIdentity represents violations in IAM, RBAC, or Principal-based policies.
	CategoryIdentity
	// CategoryResource represents violations in Resource-based policies (e.g., Bucket Policies).
	CategoryResource
)

const (
	suffixIdentity = "_via_identity"
	suffixResource = "_via_resource"
)

// classifyProperty derives the security category from the property path suffix.
func classifyProperty(path string) Category {
	switch {
	case strings.Contains(path, suffixIdentity):
		return CategoryIdentity
	case strings.Contains(path, suffixResource):
		return CategoryResource
	default:
		return CategoryUnknown
	}
}

// Misconfiguration provides the "Logic Proof" for a security violation.
// It captures the specific field, the observed state, and the failed logic gate.
type Misconfiguration struct {
	// Property is the field path (e.g., "properties.public_access_block.block_public_acls").
	Property string `json:"property"`

	// ActualValue is the state observed during evaluation.
	ActualValue any `json:"actual_value"`

	// Operator is the failed logic gate (e.g., "eq", "missing").
	Operator predicate.Operator `json:"operator"`

	// UnsafeValue is the threshold or value defined in the policy.
	UnsafeValue any `json:"unsafe_value,omitempty"`

	// Category identifies if the proof is identity or resource bound.
	Category Category `json:"-"`
}

// DisplayProperty strips the internal "properties." prefix for human-friendly reporting.
func (m Misconfiguration) DisplayProperty() string {
	// Reusing the logic from the predicate.FieldPath refactor.
	return strings.TrimPrefix(m.Property, propertiesPathPrefix)
}

// IsMissing reports whether the violation was caused by the absence of a required field.
func (m Misconfiguration) IsMissing() bool {
	return m.Operator == predicate.OpMissing || m.ActualValue == nil
}

// Sanitized returns a copy of the misconfiguration with the actual value redacted.
// This is used for generating public-facing reports where sensitive data must be hidden.
func (m Misconfiguration) Sanitized() Misconfiguration {
	m.ActualValue = kernel.Redacted
	return m
}

// String returns a human-readable explanation of the violation.
func (m Misconfiguration) String() string {
	path := m.DisplayProperty()

	if m.IsMissing() {
		return fmt.Sprintf("property %q is missing", path)
	}

	switch m.Operator {
	case predicate.OpEq:
		return fmt.Sprintf("property %q has unsafe value: %v", path, m.ActualValue)

	case predicate.OpNe:
		return fmt.Sprintf("property %q value %v is unsafe", path, m.ActualValue)

	case predicate.OpContains:
		return fmt.Sprintf("property %q contains unsafe element: %v", path, m.ActualValue)

	case predicate.OpIn:
		return fmt.Sprintf("property %q value %v is within unsafe set %v", path, m.ActualValue, m.UnsafeValue)

	case predicate.OpAnyMatch:
		return fmt.Sprintf("one or more items in %q matched unsafe criteria", path)

	default:
		// Fallback for less common or custom operators.
		return fmt.Sprintf("property %q (value: %v) failed %s check", path, m.ActualValue, m.Operator)
	}
}

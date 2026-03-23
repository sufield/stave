package policy

import (
	"encoding/json"
	"fmt"
)

// Operand wraps a predicate comparison value with type safety.
// The inner raw value is restricted to: bool, string, float64, int,
// []string, []any, map[string]any, or nil.
type Operand struct{ raw any }

// Bool creates an Operand holding a bool.
func Bool(v bool) Operand { return Operand{raw: v} }

// Str creates an Operand holding a string.
func Str(v string) Operand { return Operand{raw: v} }

// NewOperand creates an Operand from a dynamic value (e.g. YAML unmarshal output).
func NewOperand(v any) Operand { return Operand{raw: v} }

// Raw returns the underlying value for operator evaluation.
func (o Operand) Raw() any { return o.raw }

// AsBool returns the value as a bool if it is one.
func (o Operand) AsBool() (bool, bool) {
	v, ok := o.raw.(bool)
	return v, ok
}

// AsString returns the value as a string if it is one.
func (o Operand) AsString() (string, bool) {
	v, ok := o.raw.(string)
	return v, ok
}

// AsNumber returns the value as a float64, converting int if needed.
func (o Operand) AsNumber() (float64, bool) {
	switch v := o.raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	default:
		return 0, false
	}
}

// AsStringSlice returns the value as a []string if it is one.
func (o Operand) AsStringSlice() ([]string, bool) {
	v, ok := o.raw.([]string)
	return v, ok
}

// String implements fmt.Stringer.
func (o Operand) String() string { return fmt.Sprint(o.raw) }

// IsZero reports whether the operand holds nil (supports yaml omitempty).
func (o Operand) IsZero() bool { return o.raw == nil }

// MarshalJSON encodes the raw value.
func (o Operand) MarshalJSON() ([]byte, error) { return json.Marshal(o.raw) }

// UnmarshalJSON decodes into the raw value.
func (o *Operand) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, &o.raw) }

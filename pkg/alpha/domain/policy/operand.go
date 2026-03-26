package policy

import "encoding/json"

// Operand wraps a predicate comparison value with type safety.
// It handles the polymorphism of JSON/YAML inputs (where a value might be
// a string, number, bool, or list) and provides safe access via Raw().
type Operand struct{ raw any }

// Bool creates an Operand holding a bool.
func Bool(v bool) Operand { return Operand{raw: v} }

// Str creates an Operand holding a string.
func Str(v string) Operand { return Operand{raw: v} }

// NewOperand creates an Operand from a dynamic value (e.g. YAML unmarshal output).
func NewOperand(v any) Operand { return Operand{raw: v} }

// Raw returns the underlying value for operator evaluation.
func (o Operand) Raw() any { return o.raw }

// MarshalJSON encodes the raw value.
func (o Operand) MarshalJSON() ([]byte, error) { return json.Marshal(o.raw) }

// UnmarshalJSON decodes into the raw value.
func (o *Operand) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, &o.raw) }

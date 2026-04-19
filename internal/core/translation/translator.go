package translation

import (
	"fmt"
	"strings"
)

// FieldRegistry maps observation field paths (e.g.
// "storage.access.has_wildcard_principal") to their plain-language
// one-liner. A nil or missing entry is a signal to fall back to the
// raw DSL rendering.
type FieldRegistry map[string]string

// Lookup returns (prose, ok). Callers fall back to the raw field
// path when ok is false.
func (r FieldRegistry) Lookup(key string) (string, bool) {
	if r == nil {
		return "", false
	}
	v, ok := r[key]
	return v, ok
}

// Clause is the translator's input — the same triple
// (observation, operator, expected vs observed) that
// evaluation.MatchedClause carries, decoupled from the evaluation
// package to keep this package free of core-layer deps.
type Clause struct {
	ObservationKey string
	Operator       string
	ExpectedValue  any
	ObservedValue  any
}

// RenderClause produces one line of plain English prose for a
// matched predicate clause. See docs/product/metrics.md § Metric 5.
//
// Output shape:
//
//	"{field prose} must {operator verb} {expected}, but is {observed}"
//
// Edge-case rules:
//   - Unknown ObservationKey: falls back to the raw key + raw op +
//     literal values. Output is still readable; TODO in the
//     registry flags the gap.
//   - Unknown operator: falls back to the raw op string.
//   - nil / empty observed value: renders as "not set".
//   - "present"/"missing" operators drop the "must X {expected}"
//     form because the expected value is a bool about presence
//     itself; renders as "must be set (but is not set)" style.
func RenderClause(c Clause, registry FieldRegistry) string {
	fieldProse, found := registry.Lookup(c.ObservationKey)
	if !found {
		fieldProse = c.ObservationKey
	}

	opProse := OperatorProse(c.Operator)

	switch c.Operator {
	case "present":
		if c.ObservedValue == nil {
			return fieldProse + " must be set, but is not set"
		}
		return fieldProse + " must be set (observed: " + formatValue(c.ObservedValue) + ")"
	case "missing":
		if c.ObservedValue == nil {
			return fieldProse + " must be missing (and is)"
		}
		return fieldProse + " must be missing, but is " + formatValue(c.ObservedValue)
	}

	return fmt.Sprintf("%s must %s %s, but is %s",
		fieldProse,
		opProse,
		formatValue(c.ExpectedValue),
		formatValue(c.ObservedValue),
	)
}

// formatValue returns a reader-friendly literal for a value. Bools
// render as "true"/"false"; strings are quoted; nil renders as "not
// set"; slices collapse to JSON-ish `[a, b]` form.
func formatValue(v any) string {
	if v == nil {
		return "not set"
	}
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		if t == "" {
			return "an empty string"
		}
		return "\"" + t + "\""
	case []any:
		parts := make([]string, len(t))
		for i, it := range t {
			parts[i] = formatValue(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(t))
		for i, it := range t {
			parts[i] = "\"" + it + "\""
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(t)
	}
}

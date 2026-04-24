package observations

import (
	"strings"
)

// normalizeProperties recursively walks a property map and coerces
// string-encoded booleans and numbers to their native Go types.
//
// This ensures downstream evaluation (including CEL) sees consistent
// types regardless of how upstream extractors serialized the values.
//
// Rules:
//   - "true"/"false" (case-insensitive, trimmed) → bool
//   - Strings that parse as float64 → float64 (only pure numeric strings)
//   - nil values are preserved (field-absence semantics)
//   - Nested maps are recursed
//   - Slices are element-wise normalized
//   - Already-typed values (bool, float64, int) are left unchanged
func normalizeProperties(m map[string]any) {
	for k, v := range m {
		m[k] = normalizeValue(v)
	}
}

func normalizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		normalizeProperties(val)
		return val
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = normalizeValue(elem)
		}
		return out
	case string:
		return coerceString(val)
	default:
		return v
	}
}

// coerceString converts string-encoded booleans to native types.
// Numeric strings are intentionally preserved as strings — a property
// value of "123" may be a port number, version string, or ID that
// downstream CEL predicates use with string operations (contains,
// matches, startsWith). Coercing to float64 breaks those predicates.
//
// Only unambiguous boolean conversions are performed:
//   - "true"/"false" (after trim+lower) → bool
func coerceString(s string) any {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return s
	}

	switch strings.ToLower(trimmed) {
	case "true":
		return true
	case "false":
		return false
	}

	return s
}

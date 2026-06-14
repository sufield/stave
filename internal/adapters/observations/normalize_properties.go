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
//   - nil values are preserved (field-absence semantics)
//   - Nested maps are recursed
//   - Slices are element-wise normalized (new slice — slices in Go
//     are value types but their backing arrays are shared, so we
//     allocate a new one rather than mutate the caller's array
//     header in place)
//   - Already-typed values (bool, float64, int) are left unchanged
//
// Mutation strategy: maps are mutated in place at every nesting
// level. The earlier shape mutated the top-level map but cloned
// nested maps; that hybrid surprised callers reasoning about
// aliased sub-trees. Uniform in-place mutation matches the public
// contract (caller hands us a map, we normalize it) and matches
// what every caller already does (they pass owned maps).
func normalizeProperties(m map[string]any) {
	for k, v := range m {
		m[k] = normalizeValue(v)
	}
}

func normalizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		// Mutate in place to match normalizeProperties' top-level
		// strategy (see comment on normalizeProperties).
		for k, vv := range val {
			val[k] = normalizeValue(vv)
		}
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
		// Return the trimmed (empty) value rather than the original
		// untrimmed input. The earlier shape returned s, which let
		// whitespace-only strings ("   ", "\t\n") survive normalization
		// even though every downstream consumer treats whitespace-only
		// as equivalent to absent.
		return trimmed
	}

	if strings.EqualFold(trimmed, "true") {
		return true
	}
	if strings.EqualFold(trimmed, "false") {
		return false
	}

	return s
}

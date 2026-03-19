package json

import (
	"strconv"
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
		for i, elem := range val {
			val[i] = normalizeValue(elem)
		}
		return val
	case string:
		return coerceString(val)
	default:
		return v
	}
}

// coerceString converts string-encoded booleans and numbers to native types.
// Only unambiguous conversions are performed:
//   - "true"/"false" (after trim+lower) → bool
//   - Pure numeric strings (not hex, not empty) → float64
func coerceString(s string) any {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return s // preserve empty/whitespace strings as-is
	}

	// Boolean coercion (case-insensitive)
	switch strings.ToLower(trimmed) {
	case "true":
		return true
	case "false":
		return false
	}

	// Numeric coercion — only pure decimal numbers, no hex/octal
	if isNumericCandidate(trimmed) {
		if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
			return f
		}
	}

	return s
}

// isNumericCandidate checks if a string looks like a decimal number.
// Rejects hex (0x), octal (0o), binary (0b), and strings starting with
// letters to avoid false positives on identifiers like "s3://bucket".
func isNumericCandidate(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := s[0]
	// Must start with digit, minus, or dot
	if first != '-' && first != '.' && (first < '0' || first > '9') {
		return false
	}
	// Reject 0x, 0o, 0b prefixes
	if len(s) > 1 && first == '0' {
		second := s[1]
		if second == 'x' || second == 'X' || second == 'o' || second == 'O' || second == 'b' || second == 'B' {
			return false
		}
	}
	return true
}

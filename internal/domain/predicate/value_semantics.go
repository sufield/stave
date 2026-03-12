package predicate

import (
	"regexp"
	"strings"
)

// value_semantics.go defines normalization and emptiness semantics for
// predicate evaluation over dynamic values.

// StringContains checks if the string representation of val contains substring.
// Returns false if either input cannot be treated as a string.
func StringContains(val, substring any) bool {
	s, ok1 := toString(val)
	sub, ok2 := toString(substring)
	if !ok1 || !ok2 {
		return false
	}
	return strings.Contains(s, sub)
}

// StringMatches checks if the string representation of val matches
// the regex pattern provided in pattern.
func StringMatches(val, pattern any) bool {
	s, ok1 := toString(val)
	p, ok2 := toString(pattern)
	if !ok1 || !ok2 {
		return false
	}
	matched, err := regexp.MatchString(p, s)
	return err == nil && matched
}

// IsEmptyValue checks if a value is semantically "empty".
// Supported types:
//   - nil: always true
//   - string: true if only whitespace
//   - slices/maps: true if length is 0
//   - pointers: true if nil or the pointed-to value is empty
func IsEmptyValue(v any) bool {
	if v == nil {
		return true
	}

	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val) == ""
	case []string:
		return len(val) == 0
	case []any:
		return len(val) == 0
	case map[string]any:
		return len(val) == 0
	case map[string]string:
		return len(val) == 0
	case *string:
		return val == nil || strings.TrimSpace(*val) == ""
	}

	// For other types (int, bool, etc.), a present value is never "empty"
	// even if it is the type's zero-value (like 0 or false).
	return false
}

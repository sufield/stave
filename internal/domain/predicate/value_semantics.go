package predicate

import "strings"

// value_semantics.go defines normalization and emptiness semantics for
// predicate evaluation over dynamic values.

// StringContains checks if string a contains substring b.
func StringContains(a, b any) bool {
	sa, okA := a.(string)
	sb, okB := b.(string)
	if !okA || !okB {
		return false
	}
	return strings.Contains(sa, sb)
}

// IsEmptyValue checks if a value is considered "empty" or "missing".
func IsEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val) == ""
	case *string:
		return val == nil || strings.TrimSpace(*val) == ""
	}
	return false
}

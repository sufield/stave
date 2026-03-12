package predicate

import (
	"slices"
)

// ValueInList reports whether fieldValue is contained within listValue.
// It supports slices of strings or slices of any.
func ValueInList(fieldValue, listValue any) bool {
	switch list := listValue.(type) {
	case []string:
		s, ok := toString(fieldValue)
		return ok && slices.Contains(list, s)
	case []any:
		// For string-like values, use exact string matching (not EqualValues)
		// to preserve case-sensitive semantics in []any lists.
		if s, ok := toString(fieldValue); ok {
			for _, item := range list {
				if is, ok := toString(item); ok && s == is {
					return true
				}
			}
			return false
		}
		for _, item := range list {
			if EqualValues(fieldValue, item) {
				return true
			}
		}
	}
	return false
}

// IsEmptyList returns true if v is nil, an empty slice, or not a slice at all.
func IsEmptyList(v any) bool {
	if v == nil {
		return true
	}
	switch list := v.(type) {
	case []any:
		return len(list) == 0
	case []string:
		return len(list) == 0
	default:
		return true // Non-slice types are treated as "empty" in list contexts
	}
}

// ListHasElementsNotIn reports true if listA contains any element that is
// not present in listB. This is effectively a "Not Subset Of" check.
func ListHasElementsNotIn(listA, listB any) bool {
	setB, ok := toStringSet(listB)
	if !ok {
		// If listB isn't a valid list, then any item in listA is "not in listB"
		return !IsEmptyList(listA)
	}

	// Iterate listA and return true on the first item not found in setB
	switch values := listA.(type) {
	case []string:
		for _, s := range values {
			if _, ok := setB[s]; !ok {
				return true
			}
		}
	case []any:
		for _, item := range values {
			if s, ok := toString(item); ok {
				if _, exists := setB[s]; !exists {
					return true
				}
			} else {
				// Item in listA cannot be converted to string;
				// since setB only contains strings, this item is "not in B".
				return true
			}
		}
	}
	return false
}

// toStringSet converts a slice into a map for O(1) lookups.
func toStringSet(list any) (map[string]struct{}, bool) {
	switch values := list.(type) {
	case []string:
		set := make(map[string]struct{}, len(values))
		for _, s := range values {
			set[s] = struct{}{}
		}
		return set, true
	case []any:
		set := make(map[string]struct{}, len(values))
		for _, item := range values {
			if s, ok := toString(item); ok {
				set[s] = struct{}{}
			}
		}
		return set, true
	default:
		return nil, false
	}
}

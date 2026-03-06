package predicate

import "slices"

// ValueInList checks if a value is contained in a list.
func ValueInList(fieldValue, listValue any) bool {
	switch list := listValue.(type) {
	case []any:
		return valueInAnyList(fieldValue, list)
	case []string:
		return valueInStringList(fieldValue, list)
	default:
		return false
	}
}

// IsEmptyList checks if a value is an empty list or not a list.
func IsEmptyList(v any) bool {
	switch list := v.(type) {
	case nil:
		return true
	case []any:
		return len(list) == 0
	case []string:
		return len(list) == 0
	default:
		return true // not a list = treat as empty
	}
}

// ListHasElementsNotIn checks if listA contains any element not in listB.
func ListHasElementsNotIn(listA, listB any) bool {
	setB, ok := stringSetFromList(listB)
	if !ok {
		return true // listB is not a valid list, so listA has "extra" elements
	}
	return listContainsItemOutsideSet(listA, setB)
}

func stringSetFromList(list any) (map[string]struct{}, bool) {
	set := make(map[string]struct{})
	switch values := list.(type) {
	case []any:
		for _, item := range values {
			if s, ok := item.(string); ok {
				set[s] = struct{}{}
			}
		}
		return set, true
	case []string:
		for _, item := range values {
			set[item] = struct{}{}
		}
		return set, true
	default:
		return nil, false
	}
}

func listContainsItemOutsideSet(list any, allowed map[string]struct{}) bool {
	switch values := list.(type) {
	case []any:
		for _, item := range values {
			if s, ok := item.(string); ok && !setContains(allowed, s) {
				return true
			}
		}
	case []string:
		for _, item := range values {
			if !setContains(allowed, item) {
				return true
			}
		}
	}
	return false
}

func setContains(set map[string]struct{}, value string) bool {
	_, ok := set[value]
	return ok
}

func valueInStringList(fieldValue any, list []string) bool {
	fieldStr, ok := toString(fieldValue)
	if !ok {
		return false
	}
	if len(list) == 0 {
		return false
	}
	return slices.Contains(list, fieldStr)
}

func valueInAnyList(fieldValue any, list []any) bool {
	if len(list) == 0 {
		return false
	}

	// Preserve existing semantics: for string-like needles, only exact string
	// items match in []any lists.
	if fieldStr, isString := toString(fieldValue); isString {
		for _, item := range list {
			if itemStr, ok := toString(item); ok && fieldStr == itemStr {
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
	return false
}

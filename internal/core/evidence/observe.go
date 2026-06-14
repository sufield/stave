package evidence

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// RedactedValue is the placeholder for sensitive observation values.
const RedactedValue = "[REDACTED]"

// ExtractObservationProperties resolves dot-path fields from a property
// map and returns typed observation entries. Sensitive field values are
// replaced with RedactedValue.
//
// The isSensitive callback checks whether a field's leaf name indicates
// a sensitive value. It is injected to avoid importing the sanitize
// package from core.
func ExtractObservationProperties(
	properties map[string]any,
	fields []string,
	isSensitive func(string) bool,
) []ObservationProperty {
	if len(properties) == 0 || len(fields) == 0 {
		return nil
	}

	var out []ObservationProperty
	for _, field := range fields {
		val, ok := resolveDotPath(properties, field)
		if !ok {
			continue
		}

		strVal := fmt.Sprintf("%v", val)
		leaf := leafName(field)
		if isSensitive != nil && isSensitive(leaf) {
			strVal = RedactedValue
		}

		out = append(out, ObservationProperty{
			Field: field,
			Value: strVal,
		})
	}

	slices.SortFunc(out, func(a, b ObservationProperty) int {
		return cmp.Compare(a.Field, b.Field)
	})
	return out
}

// resolveDotPath traverses nested maps following a dot-separated path.
func resolveDotPath(m map[string]any, path string) (any, bool) {
	var current any = m
	for path != "" {
		var part string
		part, path, _ = strings.Cut(path, ".")
		cm, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = cm[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// leafName returns the last segment of a dot-separated path.
func leafName(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return path
}

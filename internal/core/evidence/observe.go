package evidence

import (
	"fmt"
	"sort"
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

	sort.Slice(out, func(i, j int) bool {
		return out[i].Field < out[j].Field
	})
	return out
}

// resolveDotPath traverses nested maps following a dot-separated path.
func resolveDotPath(m map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var current any = m
	for _, part := range parts {
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

package maps

import "strings"

// Value wraps raw adapter maps and provides typed extraction helpers.
type Value struct {
	data any
}

// ParseMap creates a typed parser wrapper over a raw map payload.
func ParseMap(m map[string]any) Value {
	return Value{data: m}
}

// IsMissing reports whether the wrapped value is absent.
func (v Value) IsMissing() bool {
	return v.data == nil
}

// Get returns a child value by key from the wrapped map.
func (v Value) Get(key string) Value {
	return Value{data: v.asMap()[key]}
}

// GetMap reads a nested map key and returns a new parser wrapper.
func (v Value) GetMap(key string) Value {
	next, _ := v.asMap()[key].(map[string]any)
	return Value{data: next}
}

// GetPath reads nested keys from dot notation, for example "a.b.c".
func (v Value) GetPath(path string) Value {
	if strings.TrimSpace(path) == "" {
		return Value{}
	}

	current := v
	for part := range strings.SplitSeq(path, ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return Value{}
		}
		current = current.Get(part)
		if current.IsMissing() {
			return current
		}
	}
	return current
}

// Bool interprets the wrapped value as bool.
func (v Value) Bool() bool {
	val, _ := v.data.(bool)
	return val
}

// String interprets the wrapped value as string and trims surrounding whitespace.
func (v Value) String() string {
	val, _ := v.data.(string)
	return strings.TrimSpace(val)
}

// Any returns the wrapped raw value.
func (v Value) Any() any {
	return v.data
}

// StringSlice reads and normalizes the wrapped value as []string.
func (v Value) StringSlice() []string {
	var raw []string

	switch items := v.data.(type) {
	case []string:
		raw = items
	case []any:
		raw = make([]string, 0, len(items))
		for _, item := range items {
			if s, ok := item.(string); ok {
				raw = append(raw, s)
			}
		}
	default:
		return nil
	}

	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// StringMap reads and normalizes the wrapped value as map[string]string.
func (v Value) StringMap() map[string]string {
	switch entries := v.data.(type) {
	case map[string]any:
		return stringMapFromAny(entries)
	case map[string]string:
		return stringMapFromStrings(entries)
	default:
		return map[string]string{}
	}
}

func stringMapFromAny(entries map[string]any) map[string]string {
	out := make(map[string]string, len(entries))
	for key, value := range entries {
		strValue, ok := value.(string)
		if !ok {
			continue
		}
		normalizedKey, normalizedValue, ok := normalizeStringMapEntry(key, strValue)
		if ok {
			out[normalizedKey] = normalizedValue
		}
	}
	return out
}

func stringMapFromStrings(entries map[string]string) map[string]string {
	out := make(map[string]string, len(entries))
	for key, value := range entries {
		normalizedKey, normalizedValue, ok := normalizeStringMapEntry(key, value)
		if ok {
			out[normalizedKey] = normalizedValue
		}
	}
	return out
}

func normalizeStringMapEntry(key, value string) (string, string, bool) {
	normalizedKey := strings.TrimSpace(key)
	normalizedValue := strings.TrimSpace(value)
	if normalizedKey == "" || normalizedValue == "" {
		return "", "", false
	}
	return normalizedKey, normalizedValue, true
}

func (v Value) asMap() map[string]any {
	m, _ := v.data.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

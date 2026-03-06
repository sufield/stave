package kernel

import (
	"encoding/json"
	"maps"
	"sort"
)

// Ensure SanitizableMap implements json.Marshaler and json.Unmarshaler.
var (
	_ json.Marshaler   = SanitizableMap{}
	_ json.Unmarshaler = (*SanitizableMap)(nil)
)

// SanitizableMap is a string-to-string map where individual keys can be
// marked sensitive. Sensitive keys are sanitized in MarshalJSON and Sanitized(),
// but always accessible via Get() for internal logic.
type SanitizableMap struct {
	entries   map[string]string
	sensitive map[string]bool
}

// NewSanitizableMap creates a SanitizableMap from a plain map.
// All keys are non-sensitive by default.
func NewSanitizableMap(m map[string]string) SanitizableMap {
	return SanitizableMap{
		entries:   maps.Clone(m),
		sensitive: make(map[string]bool),
	}
}

// Clone returns a deep copy of the map state (entries and sensitive flags).
// Use this when callers need an isolated copy before mutation.
func (r SanitizableMap) Clone() SanitizableMap {
	return SanitizableMap{
		entries:   maps.Clone(r.entries),
		sensitive: maps.Clone(r.sensitive),
	}
}

// Set adds or updates a key-value pair as non-sensitive.
func (r *SanitizableMap) Set(key, value string) {
	r.ensureInit()
	r.entries[key] = value
	delete(r.sensitive, key)
}

// SetSensitive adds or updates a key-value pair as sensitive.
// The value will be sanitized in JSON output and Sanitized() calls.
func (r *SanitizableMap) SetSensitive(key, value string) {
	r.ensureInit()
	r.entries[key] = value
	r.sensitive[key] = true
}

// Get returns the raw value for a key, regardless of sensitivity.
func (r SanitizableMap) Get(key string) (string, bool) {
	if r.entries == nil {
		return "", false
	}
	v, ok := r.entries[key]
	return v, ok
}

// Sanitized returns the value for a key, sanitizing it if sensitive.
func (r SanitizableMap) Sanitized(key string) string {
	if r.entries == nil {
		return ""
	}
	v, ok := r.entries[key]
	if !ok {
		return ""
	}
	if r.sensitive[key] {
		return SanitizedValue
	}
	return v
}

// Keys returns all keys in sorted order for deterministic iteration.
func (r SanitizableMap) Keys() []string {
	if r.entries == nil {
		return nil
	}
	keys := make([]string, 0, len(r.entries))
	for k := range r.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len returns the number of entries.
func (r SanitizableMap) Len() int {
	return len(r.entries)
}

// MarshalJSON serializes the map with sensitive values sanitized.
// Uses a proxy map so encoding/json handles escaping and key sorting.
func (r SanitizableMap) MarshalJSON() ([]byte, error) {
	if len(r.entries) == 0 {
		return []byte("{}"), nil
	}

	// Fast path: no sensitive keys, so we can marshal entries directly.
	if len(r.sensitive) == 0 {
		return json.Marshal(r.entries)
	}

	proxy := make(map[string]string, len(r.entries))
	for k, v := range r.entries {
		if r.sensitive[k] {
			proxy[k] = SanitizedValue
			continue
		}
		proxy[k] = v
	}
	return json.Marshal(proxy)
}

// UnmarshalJSON deserializes a JSON object into the map.
// All keys are treated as non-sensitive after deserialization.
func (r *SanitizableMap) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	r.entries = m
	r.sensitive = make(map[string]bool)
	return nil
}

// ensureInit ensures internal maps are allocated.
func (r *SanitizableMap) ensureInit() {
	if r.entries == nil {
		r.entries = make(map[string]string)
	}
	if r.sensitive == nil {
		r.sensitive = make(map[string]bool)
	}
}

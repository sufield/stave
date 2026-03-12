package kernel

import (
	"encoding/json"
	"maps"
	"slices"
)

// Ensure SanitizableMap implements standard interfaces.
var (
	_ json.Marshaler   = SanitizableMap{}
	_ json.Unmarshaler = (*SanitizableMap)(nil)
)

// SanitizableMap is a specialized map where specific keys can be flagged as sensitive.
// Sensitive values are masked during JSON serialization and public access,
// but remain accessible for internal processing.
type SanitizableMap struct {
	entries   map[string]string
	sensitive map[string]struct{} // Set pattern using struct{} for zero memory overhead
}

// NewSanitizableMap initializes a map with the provided data.
// All keys are non-sensitive by default.
func NewSanitizableMap(m map[string]string) SanitizableMap {
	return SanitizableMap{
		entries:   maps.Clone(m),
		sensitive: make(map[string]struct{}),
	}
}

// Set adds or updates a non-sensitive key-value pair.
func (m *SanitizableMap) Set(key, value string) {
	m.ensureInit()
	m.entries[key] = value
	delete(m.sensitive, key)
}

// SetSensitive adds or updates a key-value pair and marks it as sensitive.
func (m *SanitizableMap) SetSensitive(key, value string) {
	m.ensureInit()
	m.entries[key] = value
	m.sensitive[key] = struct{}{}
}

// Get returns the raw value and a boolean indicating if the key exists.
func (m SanitizableMap) Get(key string) (string, bool) {
	v, ok := m.entries[key]
	return v, ok
}

// Sanitized returns the value for a key, redacting it if it is marked sensitive.
func (m SanitizableMap) Sanitized(key string) string {
	v, ok := m.entries[key]
	if !ok {
		return ""
	}
	if _, isSensitive := m.sensitive[key]; isSensitive {
		return SanitizedValue
	}
	return v
}

// Keys returns all keys in deterministic (sorted) order.
func (m SanitizableMap) Keys() []string {
	if len(m.entries) == 0 {
		return nil
	}
	k := make([]string, 0, len(m.entries))
	for key := range m.entries {
		k = append(k, key)
	}
	slices.Sort(k)
	return k
}

// Len returns the number of entries in the map.
func (m SanitizableMap) Len() int {
	return len(m.entries)
}

// Clone returns a deep copy of the map and its sensitivity state.
func (m SanitizableMap) Clone() SanitizableMap {
	return SanitizableMap{
		entries:   maps.Clone(m.entries),
		sensitive: maps.Clone(m.sensitive),
	}
}

// MarshalJSON redacts sensitive values before serialization.
func (m SanitizableMap) MarshalJSON() ([]byte, error) {
	if len(m.entries) == 0 {
		return []byte("{}"), nil
	}

	// Fast path: nothing to redact
	if len(m.sensitive) == 0 {
		return json.Marshal(m.entries)
	}

	proxy := make(map[string]string, len(m.entries))
	for k, v := range m.entries {
		if _, isSensitive := m.sensitive[k]; isSensitive {
			proxy[k] = SanitizedValue
		} else {
			proxy[k] = v
		}
	}
	return json.Marshal(proxy)
}

// UnmarshalJSON implements deserialization.
// Note: Unmarshaled maps treat all keys as non-sensitive by default.
func (m *SanitizableMap) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.entries = raw
	m.sensitive = make(map[string]struct{})
	return nil
}

func (m *SanitizableMap) ensureInit() {
	if m.entries == nil {
		m.entries = make(map[string]string)
	}
	if m.sensitive == nil {
		m.sensitive = make(map[string]struct{})
	}
}

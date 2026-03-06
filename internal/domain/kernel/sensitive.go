package kernel

import "encoding/json"

// SanitizedValue is the placeholder shown in place of sensitive data.
const SanitizedValue = "[SANITIZED]"

// Sensitive wraps a string value that must never appear in output.
// String(), GoString(), MarshalJSON(), and MarshalYAML() all return [SANITIZED].
// Use .Value() to access the raw string - grep for ".Value()" to audit access.
type Sensitive string

// String returns [SANITIZED], preventing accidental printing via fmt.
func (s Sensitive) String() string { return SanitizedValue }

// GoString returns [SANITIZED], preventing accidental printing via %#v.
func (s Sensitive) GoString() string { return SanitizedValue }

// MarshalJSON returns "[SANITIZED]" as a JSON string.
func (s Sensitive) MarshalJSON() ([]byte, error) {
	return []byte(`"` + SanitizedValue + `"`), nil
}

// MarshalYAML returns [SANITIZED] as the YAML value.
func (s Sensitive) MarshalYAML() (any, error) {
	return SanitizedValue, nil
}

// Value returns the raw underlying string. Grep ".Value()" to audit all access.
func (s Sensitive) Value() string { return string(s) }

// UnmarshalJSON ensures that incoming data is wrapped immediately.
func (s *Sensitive) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = Sensitive(raw)
	return nil
}

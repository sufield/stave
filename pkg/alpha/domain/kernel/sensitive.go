package kernel

import "encoding/json"

// Redacted is the placeholder shown in place of sensitive data in public outputs.
const Redacted = "[SANITIZED]"

// Sensitive wraps a string that must be shielded from logs, JSON, and YAML output.
// It implements standard formatting and marshaling interfaces to prevent leaks.
//
// To access the raw data, use .Value(). Grep for ".Value()" to audit sensitive access.
type Sensitive string

// Value returns the raw underlying string. Grep ".Value()" to audit all access.
func (s Sensitive) Value() string {
	return string(s)
}

// String satisfies fmt.Stringer, returning a redacted placeholder.
func (s Sensitive) String() string {
	return Redacted
}

// GoString satisfies fmt.GoStringer, returning a redacted placeholder for %#v.
func (s Sensitive) GoString() string {
	return Redacted
}

// MarshalJSON implements json.Marshaler, ensuring the value is redacted in JSON.
func (s Sensitive) MarshalJSON() ([]byte, error) {
	return json.Marshal(Redacted)
}

// UnmarshalJSON implements json.Unmarshaler, wrapping raw input into the type.
func (s *Sensitive) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = Sensitive(raw)
	return nil
}

// MarshalYAML implements the YAML marshaler interface.
func (s Sensitive) MarshalYAML() (any, error) {
	return Redacted, nil
}

// UnmarshalYAML allows sensitive strings to be read from YAML configuration.
func (s *Sensitive) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	*s = Sensitive(raw)
	return nil
}

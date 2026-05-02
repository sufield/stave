package kernel

import (
	"encoding/json"
	"strings"
)

// ObservationKey is the field path an evaluation looked up to
// reach a verdict — e.g. "storage.access.public_read",
// "policy.statements[0].effect". Sourced from a
// predicate.FieldPath via FromFieldPath, with the leading
// "properties." prefix stripped so reasoning-trace consumers see
// the user-facing path rather than the internal accessor.
type ObservationKey string

// FromFieldPath converts a predicate.FieldPath-style string into an
// ObservationKey, stripping the leading "properties." accessor that
// the predicate engine prepends. The argument is typed string
// (rather than imported predicate.FieldPath) so the kernel does not
// take a dependency on internal/core/predicate.
func FromFieldPath(s string) ObservationKey {
	return ObservationKey(strings.TrimPrefix(s, "properties."))
}

// String returns the raw key.
func (k ObservationKey) String() string { return string(k) }

// IsEmpty reports whether the key is unset.
func (k ObservationKey) IsEmpty() bool { return k == "" }

// MarshalText implements encoding.TextMarshaler.
func (k ObservationKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText accepts any non-empty key — the predicate engine is
// the only writer at the moment, and it composes legal field paths
// by construction. Keep the gate light here so future synthetic
// keys (alias resolution outputs, computed projections) round-trip
// without a vocabulary check.
func (k *ObservationKey) UnmarshalText(text []byte) error {
	*k = ObservationKey(text)
	return nil
}

// MarshalJSON serialises as a JSON string.
func (k ObservationKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (k *ObservationKey) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return k.UnmarshalText([]byte(s))
}

package predicate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FieldPath is a dot-separated path identifying a field in an asset's property
// tree (e.g. "properties.storage.access.public_read"). It eagerly splits the
// path into segments so callers avoid repeated allocation during evaluation.
//
// FieldPath is immutable — all composition methods return new values.
type FieldPath struct {
	raw   string
	parts []string
}

// NewFieldPath creates a FieldPath from a dot-separated string.
// It cleans the path by removing empty segments (e.g., "a..b" becomes "a.b").
func NewFieldPath(s string) FieldPath {
	s = strings.TrimSpace(s)
	if s == "" {
		return FieldPath{}
	}

	rawParts := strings.Split(s, ".")
	parts := make([]string, 0, len(rawParts))
	for _, p := range rawParts {
		if p != "" {
			parts = append(parts, p)
		}
	}

	if len(parts) == 0 {
		return FieldPath{}
	}

	return FieldPath{
		raw:   strings.Join(parts, "."),
		parts: parts,
	}
}

// String returns the canonical dot-separated path. Implements fmt.Stringer.
func (f FieldPath) String() string { return f.raw }

// IsZero reports whether the path is empty. Supports yaml/json omitempty.
func (f FieldPath) IsZero() bool { return len(f.parts) == 0 }

// Parts returns a copy of the pre-split path segments.
// The copy prevents callers from mutating the internal state.
func (f FieldPath) Parts() []string {
	if f.IsZero() {
		return nil
	}
	return append([]string(nil), f.parts...)
}

// TrimPrefix returns the path with the given prefix removed.
func (f FieldPath) TrimPrefix(prefix string) string {
	return strings.TrimPrefix(f.raw, prefix)
}

// HasPrefix reports whether the path starts with the given prefix.
func (f FieldPath) HasPrefix(prefix string) bool {
	return strings.HasPrefix(f.raw, prefix)
}

// --- Serialization ---

// MarshalJSON converts the FieldPath to its string representation for JSON.
func (f FieldPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.raw)
}

// UnmarshalJSON parses a JSON string into a FieldPath.
func (f *FieldPath) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("predicate: invalid field path: %w", err)
	}
	*f = NewFieldPath(s)
	return nil
}

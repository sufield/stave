package predicate

import (
	"encoding/json"
	"strings"
)

// FieldPath is a dot-separated path identifying a field in an asset's property
// tree (e.g. "properties.storage.access.public_read"). It eagerly splits the
// path into segments so callers avoid repeated allocation during evaluation.
type FieldPath struct {
	path  string
	parts []string
}

// NewFieldPath creates a FieldPath, eagerly computing path segments.
func NewFieldPath(s string) FieldPath {
	if s == "" {
		return FieldPath{}
	}
	return FieldPath{path: s, parts: strings.Split(s, ".")}
}

// String returns the original dot-separated path.
func (f FieldPath) String() string { return f.path }

// IsZero reports whether the path is empty. Supports yaml omitempty.
func (f FieldPath) IsZero() bool { return f.path == "" }

// Parts returns the pre-split path segments.
func (f FieldPath) Parts() []string { return f.parts }

// TrimPrefix returns the path with the given prefix removed.
func (f FieldPath) TrimPrefix(prefix string) string {
	return strings.TrimPrefix(f.path, prefix)
}

// --- JSON ---

func (f FieldPath) MarshalJSON() ([]byte, error) { return json.Marshal(f.path) }

func (f *FieldPath) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*f = NewFieldPath(s)
	return nil
}

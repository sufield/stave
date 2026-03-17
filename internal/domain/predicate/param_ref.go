package predicate

// ParamRef is a typed reference to a control parameter name. It replaces the
// raw string used in ValueFromParam, making parameter references explicit in
// the type system. As a named string type it marshals to/from YAML and JSON
// naturally.
type ParamRef string

// String returns the parameter name.
func (p ParamRef) String() string { return string(p) }

// IsZero reports whether the reference is empty. Supports yaml omitempty.
func (p ParamRef) IsZero() bool { return p == "" }

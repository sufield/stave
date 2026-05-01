package kernel

// EnumSet is a generic set of enum-typed constants. It replaces the
// repeated `var validXxx = map[T]struct{}{...}` + `func (x T) IsValid() bool`
// pattern across closed-vocabulary types in this package.
//
// Use NewEnumSet to construct a set; iterate the source-of-truth slice
// once and reuse the resulting set for every membership check. Contains
// uses the comma-ok idiom — a single map lookup, no allocation.
type EnumSet[T comparable] map[T]struct{}

// NewEnumSet returns an EnumSet populated from the given values.
// Duplicates collapse silently — that's the set semantic.
func NewEnumSet[T comparable](values ...T) EnumSet[T] {
	s := make(EnumSet[T], len(values))
	for _, v := range values {
		s[v] = struct{}{}
	}
	return s
}

// Contains reports whether v is a member of the set. Hot path: a
// single map lookup with the comma-ok idiom.
func (s EnumSet[T]) Contains(v T) bool {
	_, ok := s[v]
	return ok
}

// Package sets provides a generic set backed by map[T]struct{}.
package sets

// Set is a generic set.
type Set[T comparable] map[T]struct{}

// New creates a Set pre-populated with items.
func New[T comparable](items ...T) Set[T] {
	s := make(Set[T], len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// Add inserts an item. Panics with a clear message when invoked on
// a nil Set: the zero-value Set has no underlying map, so a write
// would otherwise panic with the runtime's generic "assignment to
// entry in nil map" — naming the cause makes the call site
// findable. Always construct sets via New() (or a literal
// `Set[T]{}`).
func (s Set[T]) Add(item T) {
	if s == nil {
		panic("Add called on nil Set; use sets.New() to construct one")
	}
	s[item] = struct{}{}
}

// Contains reports whether item is in the set.
func (s Set[T]) Contains(item T) bool {
	_, ok := s[item]
	return ok
}

// Len returns the number of items.
func (s Set[T]) Len() int { return len(s) }

// Slice returns all items as a slice (unordered).
func (s Set[T]) Slice() []T {
	out := make([]T, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

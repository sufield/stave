// Package sets provides a generic set backed by map[T]struct{}.
//
// Nil-Set behavior:
//   - Add panics with a clear message (writes need an underlying map).
//   - Contains, Len, Slice return false / 0 / nil — read-only methods
//     are total over a nil set, matching the natural semantics of
//     reading from a nil Go map.
//
// Always construct sets via New() (or a literal `Set[T]{}`) when
// mutation is required. Reading from a zero-value Set is safe.
package sets

import (
	"maps"
	"slices"
)

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

// Contains reports whether item is in the set. A nil Set returns
// false unconditionally — the contract is "no items present" rather
// than a panic, matching Go's read-from-nil-map semantics. Earlier
// shape would have read through a nil map (also returning false),
// but the explicit guard documents the intent.
func (s Set[T]) Contains(item T) bool {
	if s == nil {
		return false
	}
	_, ok := s[item]
	return ok
}

// Len returns the number of items. A nil Set has zero items.
func (s Set[T]) Len() int {
	if s == nil {
		return 0
	}
	return len(s)
}

// Slice returns all items as a slice (unordered). A nil Set returns
// nil — distinct from a non-nil empty Set, which returns []T{}.
func (s Set[T]) Slice() []T {
	if s == nil {
		return nil
	}
	return slices.Collect(maps.Keys(s))
}

package kernel

// PredicateFunc represents a boolean predicate for values of type T.
type PredicateFunc[T any] func(T) bool

// And composes predicates with logical AND.
// It returns true only when all predicates return true.
func And[T any](preds ...PredicateFunc[T]) PredicateFunc[T] {
	return func(v T) bool {
		for _, p := range preds {
			if !p(v) {
				return false
			}
		}
		return true
	}
}

// Or composes predicates with logical OR.
// It returns true when at least one predicate returns true.
func Or[T any](preds ...PredicateFunc[T]) PredicateFunc[T] {
	return func(v T) bool {
		for _, p := range preds {
			if p(v) {
				return true
			}
		}
		return false
	}
}

// Not inverts a predicate.
func Not[T any](pred PredicateFunc[T]) PredicateFunc[T] {
	return func(v T) bool {
		return !pred(v)
	}
}

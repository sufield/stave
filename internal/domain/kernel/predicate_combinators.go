package kernel

// Predicate represents a boolean logic gate for a value of type T.
type Predicate[T any] func(T) bool

// And composes multiple predicates into a single gate using logical AND.
// It short-circuits and returns false as soon as one predicate fails.
// If no predicates are provided, it returns a predicate that is always true.
func And[T any](preds ...Predicate[T]) Predicate[T] {
	switch len(preds) {
	case 0:
		return func(T) bool { return true }
	case 1:
		return preds[0]
	}

	return func(v T) bool {
		for _, p := range preds {
			if !p(v) {
				return false
			}
		}
		return true
	}
}

// Or composes multiple predicates into a single gate using logical OR.
// It short-circuits and returns true as soon as one predicate succeeds.
// If no predicates are provided, it returns a predicate that is always false.
func Or[T any](preds ...Predicate[T]) Predicate[T] {
	switch len(preds) {
	case 0:
		return func(T) bool { return false }
	case 1:
		return preds[0]
	}

	return func(v T) bool {
		for _, p := range preds {
			if p(v) {
				return true
			}
		}
		return false
	}
}

// Not returns the logical inverse of the provided predicate.
func Not[T any](pred Predicate[T]) Predicate[T] {
	if pred == nil {
		return func(T) bool { return true }
	}
	return func(v T) bool {
		return !pred(v)
	}
}

// AlwaysTrue returns a predicate that always succeeds.
func AlwaysTrue[T any]() Predicate[T] {
	return func(T) bool { return true }
}

// AlwaysFalse returns a predicate that always fails.
func AlwaysFalse[T any]() Predicate[T] {
	return func(T) bool { return false }
}

// Package fp provides generic functional primitives for slice transformations.
package fp

// Map transforms []T → []U via fn. Returns nil for nil/empty input.
func Map[T, U any](items []T, fn func(T) U) []U {
	if len(items) == 0 {
		return nil
	}
	out := make([]U, len(items))
	for i, item := range items {
		out[i] = fn(item)
	}
	return out
}

// Filter returns elements where fn returns true. Returns nil for nil/empty input.
func Filter[T any](items []T, fn func(T) bool) []T {
	if len(items) == 0 {
		return nil
	}
	var out []T
	for _, item := range items {
		if fn(item) {
			out = append(out, item)
		}
	}
	return out
}

// CountFunc returns the count of elements where fn returns true.
func CountFunc[T any](items []T, fn func(T) bool) int {
	n := 0
	for _, item := range items {
		if fn(item) {
			n++
		}
	}
	return n
}

// ToSet builds map[T]struct{} from []T. Returns nil for nil/empty input.
func ToSet[T comparable](items []T) map[T]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[T]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

// ToMap builds map[K]V from []V using keyFn. Returns nil for nil/empty input.
func ToMap[K comparable, V any](items []V, keyFn func(V) K) map[K]V {
	if len(items) == 0 {
		return nil
	}
	out := make(map[K]V, len(items))
	for _, item := range items {
		out[keyFn(item)] = item
	}
	return out
}

// Package fp provides generic functional primitives for slice transformations.
package fp

import (
	"cmp"
	"slices"
)

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

// FilterMap applies fn to each element, keeping only those where fn returns ok=true.
// Combines Filter and Map in a single pass.
func FilterMap[T, U any](items []T, fn func(T) (U, bool)) []U {
	if len(items) == 0 {
		return nil
	}
	var out []U
	for _, item := range items {
		if v, ok := fn(item); ok {
			out = append(out, v)
		}
	}
	return out
}

// FlatMap applies fn to each element and flattens the resulting slices.
func FlatMap[T, U any](items []T, fn func(T) []U) []U {
	if len(items) == 0 {
		return nil
	}
	var out []U
	for _, item := range items {
		out = append(out, fn(item)...)
	}
	return out
}

// Flatten concatenates a slice of slices into a single slice.
func Flatten[T any](items [][]T) []T {
	if len(items) == 0 {
		return nil
	}
	var out []T
	for _, group := range items {
		out = append(out, group...)
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

// FindFunc returns the first element where fn returns true and a boolean indicating
// whether a match was found.
func FindFunc[T any](items []T, fn func(T) bool) (T, bool) {
	for _, item := range items {
		if fn(item) {
			return item, true
		}
	}
	var zero T
	return zero, false
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

// GroupBy groups slice elements by a key derived from each element.
func GroupBy[T any, K comparable](items []T, keyFn func(T) K) map[K][]T {
	if len(items) == 0 {
		return nil
	}
	out := make(map[K][]T)
	for _, item := range items {
		k := keyFn(item)
		out[k] = append(out[k], item)
	}
	return out
}

// MapKeys extracts all keys from a map as an unordered slice.
func MapKeys[K comparable, V any](m map[K]V) []K {
	if len(m) == 0 {
		return nil
	}
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// SortedKeys extracts keys from a map and returns them sorted.
func SortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	keys := MapKeys(m)
	slices.Sort(keys)
	return keys
}

// Dedupe returns a new slice with duplicate elements removed, preserving
// the order of first occurrence.
func Dedupe[T comparable](items []T) []T {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[T]struct{}, len(items))
	var out []T
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

// Zip pairs elements from two slices by index. The result length equals
// the shorter input.
func Zip[A, B any](as []A, bs []B) []Pair[A, B] {
	n := min(len(as), len(bs))
	if n == 0 {
		return nil
	}
	out := make([]Pair[A, B], n)
	for i := range n {
		out[i] = Pair[A, B]{First: as[i], Second: bs[i]}
	}
	return out
}

// Pair holds two values of potentially different types.
type Pair[A, B any] struct {
	First  A
	Second B
}

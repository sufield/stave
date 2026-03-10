// Package fp provides generic utilities that samber/lo does not cover.
//
// Most functional primitives (Map, Filter, GroupBy, etc.) come from
// [github.com/samber/lo]. This package adds only:
//   - [ToSet]: builds a membership set from a slice.
//   - [SortedKeys]: extracts map keys in sorted order.
package fp

import (
	"cmp"
	"slices"
)

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

// SortedKeys extracts keys from a map and returns them sorted.
// Returns nil for nil/empty maps.
func SortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	if len(m) == 0 {
		return nil
	}
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

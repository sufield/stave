// Package props provides type-safe nested map traversal for asset properties.
package props

// GetIn traverses a nested map[string]any using a key path and returns
// the value cast to T. Returns zero value and false if any key is
// missing or the final value cannot be cast to T.
//
// An empty path returns (zero, false) rather than the root map cast
// to T. The earlier shape returned the root unchanged, which made
// `GetIn[map[string]any](m, nil)` look like "deep-clone the map" and
// `GetIn[string](m, nil)` succeed with an empty string. Both are
// surprising — and a caller writing `path[:i]` that walked off the
// end could pass an empty slice without realizing it.
func GetIn[T any](m map[string]any, path []string) (T, bool) {
	var zero T
	if len(path) == 0 {
		return zero, false
	}
	var current any = m
	for _, key := range path {
		mp, ok := current.(map[string]any)
		if !ok {
			return zero, false
		}
		current, ok = mp[key]
		if !ok {
			return zero, false
		}
	}
	v, ok := current.(T)
	return v, ok
}

// GetString is a convenience wrapper for string properties.
func GetString(m map[string]any, path []string) string {
	v, _ := GetIn[string](m, path)
	return v
}

// GetBool is a convenience wrapper for bool properties.
func GetBool(m map[string]any, path []string) bool {
	v, _ := GetIn[bool](m, path)
	return v
}

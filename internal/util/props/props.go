// Package props provides type-safe nested map traversal for asset properties.
package props

// GetIn traverses a nested map[string]any using a key path and returns
// the value cast to T. Returns zero value and false if any key is
// missing or the final value cannot be cast to T.
func GetIn[T any](m map[string]any, path []string) (T, bool) {
	var zero T
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

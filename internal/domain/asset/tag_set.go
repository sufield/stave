package asset

import (
	"slices"
)

// TagSet is a value object for asset tags used by scope matching.
type TagSet struct {
	normalized map[string]string
	conflicts  []string
}

// NewTagSet constructs an immutable tag set from raw key/value pairs.
func NewTagSet(raw map[string]string) TagSet {
	if len(raw) == 0 {
		return TagSet{normalized: map[string]string{}}
	}

	normalized := make(map[string]string, len(raw))
	conflictSet := make(map[string]struct{})

	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		normalizedKey := tagKey(key).normalize()
		if normalizedKey.isDiscardable() {
			continue
		}
		norm := normalizedKey.string()
		if _, exists := normalized[norm]; exists {
			conflictSet[norm] = struct{}{}
			continue
		}
		normalized[norm] = raw[key]
	}

	conflicts := make([]string, 0, len(conflictSet))
	for key := range conflictSet {
		conflicts = append(conflicts, key)
	}
	slices.Sort(conflicts)

	return TagSet{
		normalized: normalized,
		conflicts:  conflicts,
	}
}

// Matches reports whether a key exists and satisfies the allowed criteria.
// If allowedValues is empty, any non-empty value for the key counts as a match.
func (ts TagSet) Matches(key string, allowedValues map[string]struct{}) bool {
	normalizedKey := tagKey(key).normalize()
	if normalizedKey.isDiscardable() {
		return false
	}

	value, ok := ts.normalized[normalizedKey.string()]
	if !ok {
		return false
	}

	normalizedValue := tagValue(value).normalize()
	if normalizedValue.isDiscardable() {
		return false
	}

	if len(allowedValues) == 0 {
		return true
	}

	_, match := allowedValues[normalizedValue.string()]
	return match
}

// HasConflicts reports whether multiple keys normalize to the same key.
func (ts TagSet) HasConflicts() bool {
	return len(ts.conflicts) > 0
}

// Conflicts returns normalized keys that had case-insensitive collisions.
func (ts TagSet) Conflicts() []string {
	return append([]string(nil), ts.conflicts...)
}

package asset

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/pkg/fp"
)

// TagConflict records a case-insensitive key collision in a TagSet.
type TagConflict struct {
	Key       string   // normalized key
	Kept      string   // raw key whose value was kept (first alphabetically)
	Discarded []string // raw keys whose values were dropped
}

// String formats the conflict for diagnostic messages.
func (c TagConflict) String() string {
	return fmt.Sprintf("%s (kept %q, discarded %s)",
		c.Key, c.Kept, formatQuoted(c.Discarded))
}

func formatQuoted(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}

// TagSet is a value object for asset tags used by scope matching.
type TagSet struct {
	normalized map[string]string
	conflicts  []TagConflict
}

// NewTagSet constructs an immutable tag set from raw key/value pairs.
func NewTagSet(raw map[string]string) TagSet {
	if len(raw) == 0 {
		return TagSet{normalized: map[string]string{}}
	}

	normalized := make(map[string]string, len(raw))
	// Track winner per normalized key so we can report kept vs discarded.
	winners := make(map[string]string)
	conflictDiscarded := make(map[string][]string)

	keys := fp.SortedKeys(raw)

	for _, key := range keys {
		normalizedKey := tagKey(key).normalize()
		if normalizedKey.isDiscardable() {
			continue
		}
		norm := normalizedKey.string()
		if _, exists := normalized[norm]; exists {
			conflictDiscarded[norm] = append(conflictDiscarded[norm], key)
			continue
		}
		normalized[norm] = raw[key]
		winners[norm] = key
	}

	conflictKeys := fp.SortedKeys(conflictDiscarded)
	conflicts := make([]TagConflict, len(conflictKeys))
	for i, norm := range conflictKeys {
		conflicts[i] = TagConflict{
			Key:       norm,
			Kept:      winners[norm],
			Discarded: conflictDiscarded[norm],
		}
	}

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

// Conflicts returns details of case-insensitive key collisions.
func (ts TagSet) Conflicts() []TagConflict {
	return slices.Clone(ts.conflicts)
}

package asset

import (
	"strings"

	"github.com/samber/lo"
)

// AssetPredicate is the domain-level evaluation-time filter.
// It operates on Asset objects after extraction is complete.
//
// This is intentionally separate from the adapter-level ScopeConfig
// (adapters/input/extract/s3/scope.go), which filters during extraction
// using raw tags and bucket names. The two serve different hexagonal
// layers and are not a duplication bug.

// AssetPredicate decides whether a single asset is in scope.
type AssetPredicate interface {
	IsInScope(a Asset) bool
}

// scopeFilter is the private implementation of AssetPredicate.
type scopeFilter struct {
	includeAll   bool
	allowlist    map[string]struct{}
	requiredTags map[string]map[string]struct{} // key -> allowed lowercase values
	requiredKeys map[string]struct{}            // keys where any non-empty value matches
}

// UniversalFilter is a null-object predicate that admits all assets.
var UniversalFilter AssetPredicate = &scopeFilter{includeAll: true}

var _ AssetPredicate = (*scopeFilter)(nil)

// DefaultHealthcareScopeFilter returns the default healthcare scope predicate.
func DefaultHealthcareScopeFilter() AssetPredicate {
	return NewScopeFilter(nil, map[string][]string{
		"DataDomain":  {"health"},
		"containsPHI": {"true"},
	})
}

// NewScopeFilterFromAllowlist creates a scope predicate with an explicit bucket allowlist.
func NewScopeFilterFromAllowlist(buckets []string) AssetPredicate {
	return NewScopeFilter(buckets, nil)
}

// NewScopeFilter creates a pre-indexed predicate for O(1) lookups.
func NewScopeFilter(allowlist []string, tagSpecs map[string][]string) AssetPredicate {
	if hasNoScopeConstraints(allowlist, tagSpecs) {
		return UniversalFilter
	}

	f := newScopeFilter(allowlist, tagSpecs)
	f.indexAllowlist(allowlist)
	f.indexTagSpecs(tagSpecs)

	if f.isConstraintFree() {
		return UniversalFilter
	}

	return f
}

func newScopeFilter(allowlist []string, tagSpecs map[string][]string) *scopeFilter {
	return &scopeFilter{
		allowlist:    make(map[string]struct{}, len(allowlist)),
		requiredTags: make(map[string]map[string]struct{}, len(tagSpecs)),
		requiredKeys: make(map[string]struct{}),
	}
}

func (f *scopeFilter) indexAllowlist(allowlist []string) {
	for _, item := range allowlist {
		normalized := allowlistEntry(item).normalize()
		if normalized.isDiscardable() {
			continue
		}
		f.allowlist[normalized.string()] = struct{}{}
	}
}

func (f *scopeFilter) indexTagSpecs(tagSpecs map[string][]string) {
	for key, values := range tagSpecs {
		f.indexTagSpec(key, values)
	}
}

func (f *scopeFilter) indexTagSpec(key string, values []string) {
	normalizedKey := tagKey(key).normalize()
	if normalizedKey.isDiscardable() {
		return
	}
	normalizedKeyValue := normalizedKey.string()
	if len(values) == 0 {
		f.requiredKeys[normalizedKeyValue] = struct{}{}
		return
	}

	valueSet := buildNormalizedTagValueSet(values)
	if len(valueSet) == 0 {
		f.requiredKeys[normalizedKeyValue] = struct{}{}
		return
	}
	f.requiredTags[normalizedKeyValue] = valueSet
}

func buildNormalizedTagValueSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalizedValue := tagValue(value).normalize()
		if normalizedValue.isDiscardable() {
			continue
		}
		set[normalizedValue.string()] = struct{}{}
	}
	return set
}

func hasNoScopeConstraints(allowlist []string, tagSpecs map[string][]string) bool {
	return len(allowlist) == 0 && len(tagSpecs) == 0
}

// IsInScope checks if an asset is in the healthcare scope.
func (f *scopeFilter) IsInScope(a Asset) bool {
	if f.isUniversal() {
		return true
	}

	if f.hasAllowlist() {
		return f.isAllowedByIdentity(a)
	}

	return f.satisfiesTagRequirements(a)
}

func (f *scopeFilter) isUniversal() bool {
	return f != nil && f.includeAll
}

func (f *scopeFilter) hasAllowlist() bool {
	return len(f.allowlist) > 0
}

func (f *scopeFilter) isConstraintFree() bool {
	return len(f.allowlist) == 0 && len(f.requiredTags) == 0 && len(f.requiredKeys) == 0
}

func (f *scopeFilter) isAllowedByIdentity(a Asset) bool {
	for _, identity := range a.Identities() {
		if _, ok := f.allowlist[identity]; ok {
			return true
		}
	}
	return false
}

func (f *scopeFilter) satisfiesTagRequirements(a Asset) bool {
	for key, allowedValues := range f.requiredTags {
		if a.HasTagMatch(key, allowedValues) {
			return true
		}
	}

	for key := range f.requiredKeys {
		if a.HasTagMatch(key, nil) {
			return true
		}
	}

	return false
}

// FilterSnapshots filters snapshots to only include assets matching the predicate.
func FilterSnapshots(predicate AssetPredicate, snapshots []Snapshot) []Snapshot {
	if predicate == nil || predicate == UniversalFilter {
		return snapshots
	}

	result := make([]Snapshot, 0, len(snapshots))
	for _, snap := range snapshots {
		if filtered, ok := snap.FilteredBy(predicate); ok {
			result = append(result, filtered)
		}
	}
	return result
}

// FilteredBy returns a snapshot with assets retained by the given predicate.
// The second return value reports whether any assets remain after filtering.
func (s Snapshot) FilteredBy(filter AssetPredicate) (Snapshot, bool) {
	if filter == nil {
		return s, len(s.Assets) > 0
	}

	kept := lo.Filter(s.Assets, func(a Asset, _ int) bool { return filter.IsInScope(a) })
	if len(kept) == 0 {
		return Snapshot{}, false
	}

	s.Assets = kept
	return s, true
}

// --- scope filter helper types ---

type allowlistEntry string

func (e allowlistEntry) normalize() allowlistEntry {
	return allowlistEntry(strings.TrimSpace(string(e)))
}

func (e allowlistEntry) isDiscardable() bool {
	return e == ""
}

func (e allowlistEntry) string() string {
	return string(e)
}

type tagKey string

func (k tagKey) normalize() tagKey {
	return tagKey(strings.ToLower(strings.TrimSpace(string(k))))
}

func (k tagKey) isDiscardable() bool {
	return k == ""
}

func (k tagKey) string() string {
	return string(k)
}

type tagValue string

func (v tagValue) normalize() tagValue {
	return tagValue(strings.ToLower(strings.TrimSpace(string(v))))
}

func (v tagValue) isDiscardable() bool {
	return v == ""
}

func (v tagValue) string() string {
	return string(v)
}

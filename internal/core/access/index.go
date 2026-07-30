// Package access defines the vendor-neutral data types Stave uses
// to represent resource-access reachability — the relation
// "principal X has actions [...] on resource Y" — independent of
// the provider that produced it.
//
// AWS-specific parsing of resource-based policies (which builds
// these types) lives in internal/platform/providers/aws/iam.
// Future GCP/Azure providers will populate the same types from
// their native policy formats.
package access

// ResourceAccessEntry represents a principal's access to a resource
// granted via a resource-based policy. The principal and grant
// source identifiers carry their cloud-native form (AWS ARN today)
// — this package treats them as opaque strings.
type ResourceAccessEntry struct {
	PrincipalARN   string
	Actions        []string
	IsCrossAccount bool
	IsPublic       bool
	GrantSource    string // resource identifier that granted access
}

// ResourceAccessIndex maps resource identifiers to the set of
// principals with access via resource-based policies. Built once
// per snapshot evaluation by a vendor-specific helper (e.g.
// providers/aws/iam.AddResourcePolicy).
type ResourceAccessIndex struct {
	entries map[string][]ResourceAccessEntry
}

// NewResourceAccessIndex creates an empty index.
func NewResourceAccessIndex() *ResourceAccessIndex {
	return &ResourceAccessIndex{
		entries: make(map[string][]ResourceAccessEntry),
	}
}

// EntriesFor returns all access entries for a resource identifier.
func (idx *ResourceAccessIndex) EntriesFor(resourceID string) []ResourceAccessEntry {
	if idx == nil {
		return nil
	}
	return idx.entries[resourceID]
}

// AddEntry adds a single access entry for a resource identifier.
func (idx *ResourceAccessIndex) AddEntry(resourceID string, entry ResourceAccessEntry) {
	if idx == nil {
		return
	}
	if idx.entries == nil {
		idx.entries = make(map[string][]ResourceAccessEntry)
	}
	idx.entries[resourceID] = append(idx.entries[resourceID], entry)
}

// Range calls fn for every (resourceID, entry) pair in the index.
func (idx *ResourceAccessIndex) Range(fn func(resourceID string, entry ResourceAccessEntry)) {
	if idx == nil || fn == nil {
		return
	}
	for rid, entries := range idx.entries {
		for _, e := range entries {
			fn(rid, e)
		}
	}
}

// HasNonDesignatedPHIAccess checks if a PHI resource has any
// accessor that is not in the designated principal set. Public
// access is never considered designated.
func (idx *ResourceAccessIndex) HasNonDesignatedPHIAccess(
	resourceID string,
	designatedPrincipals map[string]struct{},
) bool {
	if idx == nil {
		return false
	}
	for _, entry := range idx.entries[resourceID] {
		if entry.IsPublic {
			return true
		}
		if _, ok := designatedPrincipals[entry.PrincipalARN]; !ok {
			return true
		}
	}
	return false
}

// ResourcePolicyGrant is a resolved grant from a resource-based
// policy, included in extended access reports.
type ResourcePolicyGrant struct {
	ResourceARN    string
	Actions        []string
	IsCrossAccount bool
	IsPublic       bool
}

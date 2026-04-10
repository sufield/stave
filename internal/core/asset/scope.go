package asset

import (
	"strings"
)

// AuditScope defines the boundary for security evaluation.
// It determines which cloud resources are subject to policy enforcement
// based on their identity or metadata (tags).
//
// This is intentionally separate from the adapter-level ScopeConfig
// (adapters/input/extract/s3/scope.go), which filters during extraction
// using raw tags and bucket names. The two serve different hexagonal
// layers and are not a duplication bug.
type AuditScope struct {
	global       bool
	resourceIDs  map[string]struct{}            // Explicitly included resource names/ARNs
	tagSelectors map[string]map[string]struct{} // Key -> Set of allowed values
	requiredKeys map[string]struct{}            // Keys that must exist regardless of value
}

// GlobalScope is an inclusion boundary that encompasses all discovered assets.
var GlobalScope = &AuditScope{global: true}

// PHIBoundary returns the default scope for HIPAA/Healthcare compliance,
// targeting assets tagged as containing Protected Health Information.
func PHIBoundary() *AuditScope {
	return NewAuditScope(nil, map[string][]string{
		"DataDomain":  {"health"},
		"containsPHI": {"true"},
	})
}

// NewAuditScopeFromAllowlist creates a scope boundary with an explicit resource allowlist.
func NewAuditScopeFromAllowlist(resourceIDs []string) *AuditScope {
	return NewAuditScope(resourceIDs, nil)
}

// NewAuditScope initializes a scope boundary with specific inclusion criteria.
func NewAuditScope(resourceIDs []string, tagCriteria map[string][]string) *AuditScope {
	if len(resourceIDs) == 0 && len(tagCriteria) == 0 {
		return GlobalScope
	}

	s := &AuditScope{
		resourceIDs:  make(map[string]struct{}, len(resourceIDs)),
		tagSelectors: make(map[string]map[string]struct{}, len(tagCriteria)),
		requiredKeys: make(map[string]struct{}),
	}

	s.registerResourceIDs(resourceIDs)
	s.registerTagCriteria(tagCriteria)

	if s.isBoundaryEmpty() {
		return GlobalScope
	}

	return s
}

func (s *AuditScope) registerResourceIDs(ids []string) {
	for _, id := range ids {
		val := strings.TrimSpace(id)
		if val != "" {
			s.resourceIDs[val] = struct{}{}
		}
	}
}

func (s *AuditScope) registerTagCriteria(criteria map[string][]string) {
	for key, values := range criteria {
		k := strings.ToLower(strings.TrimSpace(key))
		if k == "" {
			continue
		}

		if len(values) == 0 {
			s.requiredKeys[k] = struct{}{}
			continue
		}

		valSet := make(map[string]struct{})
		for _, v := range values {
			normalized := strings.ToLower(strings.TrimSpace(v))
			if normalized != "" {
				valSet[normalized] = struct{}{}
			}
		}
		s.tagSelectors[k] = valSet
	}
}

// IsInScope evaluates if a specific cloud asset falls within the audit boundary.
func (s *AuditScope) IsInScope(a Asset) bool {
	if s == nil || s.global {
		return true
	}

	// 1. Check for explicit resource inclusion
	if len(s.resourceIDs) > 0 {
		for _, identity := range a.Identities() {
			if _, ok := s.resourceIDs[identity]; ok {
				return true
			}
		}
		return false
	}

	// 2. Check for metadata/tag-based inclusion
	for key, allowedValues := range s.tagSelectors {
		if a.HasTagMatch(key, allowedValues) {
			return true
		}
	}

	for key := range s.requiredKeys {
		if a.HasTagMatch(key, nil) {
			return true
		}
	}

	return false
}

func (s *AuditScope) isBoundaryEmpty() bool {
	return len(s.resourceIDs) == 0 && len(s.tagSelectors) == 0 && len(s.requiredKeys) == 0
}

// ApplyScopeToSnapshots returns a new set of snapshots containing only in-scope assets.
func ApplyScopeToSnapshots(scope *AuditScope, snapshots []Snapshot) []Snapshot {
	if scope == nil || scope.global {
		return snapshots
	}

	scoped := make([]Snapshot, 0, len(snapshots))
	for _, snap := range snapshots {
		if filtered, ok := snap.InScope(scope); ok {
			scoped = append(scoped, filtered)
		}
	}
	return scoped
}

// InScope returns a copy of the snapshot containing only assets matching the audit scope.
func (s Snapshot) InScope(scope *AuditScope) (Snapshot, bool) {
	if scope == nil || scope.global {
		return s, len(s.Assets) > 0
	}

	population := make([]Asset, 0, len(s.Assets))
	for _, a := range s.Assets {
		if scope.IsInScope(a) {
			population = append(population, a)
		}
	}

	if len(population) == 0 {
		return Snapshot{}, false
	}

	s.Assets = population
	return s, true
}

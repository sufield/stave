package exposure

// Permission is the internal permission bitmask used by
// visibility resolution and exposure classification.
type Permission uint32

const (
	PermRead Permission = 1 << iota
	PermWrite
	PermList
	PermMetadataRead
	PermMetadataWrite
	PermDelete

	PermAll = PermRead | PermWrite | PermList | PermMetadataRead | PermMetadataWrite | PermDelete
)

// Has reports whether target bits are set in p.
func (p Permission) Has(target Permission) bool { return p&target != 0 }

// EvidenceCategory provides type safety for tracking why an exposure was flagged.
type EvidenceCategory string

const (
	EvIdentityRead  EvidenceCategory = "identity_read"
	EvResourceRead  EvidenceCategory = "resource_read"
	EvIdentityWrite EvidenceCategory = "identity_write"
	EvResourceWrite EvidenceCategory = "resource_write"
	EvDiscovery     EvidenceCategory = "discovery"
	EvMetadataRead  EvidenceCategory = "metadata_read"
	EvMetadataWrite EvidenceCategory = "metadata_write"
	EvDelete        EvidenceCategory = "delete"
)

// EvidenceTracker manages the paths/reasons for discovered exposures.
type EvidenceTracker struct {
	sources map[EvidenceCategory][]string
}

// NewEvidenceTracker creates an initialized EvidenceTracker.
func NewEvidenceTracker() *EvidenceTracker {
	return &EvidenceTracker{sources: make(map[EvidenceCategory][]string)}
}

// Record stores the first (most relevant) evidence for a category.
func (t *EvidenceTracker) Record(cat EvidenceCategory, path []string) {
	if len(path) == 0 {
		return
	}
	if _, exists := t.sources[cat]; !exists {
		t.sources[cat] = path
	}
}

// Get returns the evidence path for a category.
func (t *EvidenceTracker) Get(cat EvidenceCategory) []string {
	return t.sources[cat]
}

// HasAny reports whether any evidence has been recorded.
func (t *EvidenceTracker) HasAny() bool {
	return len(t.sources) > 0
}

type resolutionContext struct {
	input NormalizedResourceInput
}

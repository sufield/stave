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
	EvIdentityRead      EvidenceCategory = "identity_read"
	EvResourceRead      EvidenceCategory = "resource_read"
	EvIdentityWrite     EvidenceCategory = "identity_write"
	EvResourceWrite     EvidenceCategory = "resource_write"
	EvDiscovery         EvidenceCategory = "discovery"
	EvResourceAdminRead EvidenceCategory = "resource_admin_read"
	EvDelete            EvidenceCategory = "delete"
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

// capabilitySet represents individual permission flags with lossless
// round-trip through the Permission bitmask.
type capabilitySet struct {
	Read          bool
	Write         bool
	List          bool
	Delete        bool
	MetadataRead  bool
	MetadataWrite bool
}

// ToMask converts boolean flags into a Permission bitmask.
func (cs capabilitySet) ToMask() Permission {
	var m Permission
	if cs.Read {
		m |= PermRead
	}
	if cs.Write {
		m |= PermWrite
	}
	if cs.List {
		m |= PermList
	}
	if cs.Delete {
		m |= PermDelete
	}
	if cs.MetadataRead {
		m |= PermMetadataRead
	}
	if cs.MetadataWrite {
		m |= PermMetadataWrite
	}
	return m
}

func capabilitySetFromMask(m Permission) capabilitySet {
	return capabilitySet{
		Read:          m.Has(PermRead),
		Write:         m.Has(PermWrite),
		List:          m.Has(PermList),
		Delete:        m.Has(PermDelete),
		MetadataRead:  m.Has(PermMetadataRead),
		MetadataWrite: m.Has(PermMetadataWrite),
	}
}

// writeSourceMetadata tracks which co-occurring permissions the first
// write-granting source also provided.
type writeSourceMetadata struct {
	CanAlsoRead bool
	CanAlsoList bool
}

type resolutionContext struct {
	input           NormalizedResourceInput
	identityPerms   capabilitySet
	resourcePerms   capabilitySet
	isAuthOnly      bool
	evidence        *EvidenceTracker
	writeSourceStat writeSourceMetadata
}

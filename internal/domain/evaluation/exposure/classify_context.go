package exposure

// Permission is the internal permission bitmask used by
// visibility resolution and exposure classification.
type Permission uint32

const (
	PermRead Permission = 1 << iota
	PermWrite
	PermList
	PermACLRead
	PermACLWrite
	PermDelete

	PermAll = PermRead | PermWrite | PermList | PermACLRead | PermACLWrite | PermDelete
)

// Has reports whether target bits are set in p.
func (p Permission) Has(target Permission) bool { return p&target != 0 }

// EvidenceCategory provides type safety for tracking why an exposure was flagged.
type EvidenceCategory string

const (
	EvPolicyRead     EvidenceCategory = "policy_read"
	EvACLRead        EvidenceCategory = "acl_read"
	EvPolicyWrite    EvidenceCategory = "policy_write"
	EvACLWrite       EvidenceCategory = "acl_write"
	EvList           EvidenceCategory = "list"
	EvACLReadPolicy  EvidenceCategory = "acl_read_policy"
	EvACLWritePolicy EvidenceCategory = "acl_write_policy"
	EvDelete         EvidenceCategory = "delete"
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

type bucketResolutionContext struct {
	input NormalizedBucketInput
}

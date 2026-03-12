package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// NormalizedBucketInput is the vendor-neutral representation of a bucket's
// exposure state. Adapters produce this from vendor-specific raw data.
type NormalizedBucketInput struct {
	Name              string
	Exists            bool
	ExternalReference bool
	WebsiteEnabled    bool

	// Pre-computed by the adapter from vendor-specific policy/ACL data.
	IsAuthenticatedOnly bool
	PolicyPerms         Permission
	ACLPerms            Permission
	WriteSourceHasGet   bool
	WriteSourceHasList  bool
	Evidence            *EvidenceTracker
}

// ExposureClassification represents a classified exposure vector for a resource.
type ExposureClassification struct {
	ID             kernel.ControlID      `json:"id"`
	Resource       string                `json:"resource"`
	ExposureType   string                `json:"exposure_type"`
	PrincipalScope kernel.PrincipalScope `json:"principal_scope"`
	Actions        []string              `json:"actions"`
	WriteScope     string                `json:"write_scope,omitempty"`
	EvidencePath   []string              `json:"evidence_path"`
}

// Classifications wraps a slice of classifications for JSON serialization.
type Classifications struct {
	Classifications []ExposureClassification `json:"findings"`
}

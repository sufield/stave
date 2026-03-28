package exposure

import "github.com/sufield/stave/internal/core/kernel"

// NormalizedResourceInput is the vendor-neutral representation of a resource's
// exposure state. Adapters produce this from vendor-specific raw data.
type NormalizedResourceInput struct {
	Name              string
	Exists            bool
	ExternalReference bool
	WebsiteEnabled    bool

	// Pre-computed by the adapter from vendor-specific policy/ACL data.
	IsAuthenticatedOnly bool
	IdentityPerms       Permission
	ResourcePerms       Permission
	WriteSourceHasGet   bool
	WriteSourceHasList  bool
	Evidence            *EvidenceTracker
}

// ExposureClassification represents a classified exposure vector for a resource.
type ExposureClassification struct {
	ID             kernel.ControlID      `json:"id"`
	Resource       string                `json:"resource"`
	ExposureType   Type                  `json:"exposure_type"`
	PrincipalScope kernel.PrincipalScope `json:"principal_scope"`
	Actions        []string              `json:"actions"`
	WriteScope     WriteScope            `json:"write_scope,omitempty"`
	EvidencePath   []string              `json:"evidence_path"`
}

// Classifications wraps a slice of classifications for JSON serialization.
type Classifications struct {
	Classifications []ExposureClassification `json:"findings"`
}

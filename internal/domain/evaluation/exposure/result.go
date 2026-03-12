package exposure

import "github.com/sufield/stave/internal/domain/kernel"

// VisibilityResult represents the flattened "facts" about a resource's exposure.
// These fields are typically projected into the Asset Properties during extraction.
type VisibilityResult struct {
	// Effective Permissions (Post-Governance)
	PublicRead   bool `json:"public_read"`
	PublicList   bool `json:"public_list"`
	PublicWrite  bool `json:"public_write"`
	PublicDelete bool `json:"public_delete"`
	PublicAdmin  bool `json:"public_admin"` // Combined Metadata Read/Write

	// Origin Signals (Pre-Governance)
	ReadViaIdentity  bool `json:"read_via_identity"` // e.g., IAM, RBAC
	ReadViaResource  bool `json:"read_via_resource"` // e.g., Bucket Policy, ACL
	ListViaIdentity  bool `json:"list_via_identity"`
	WriteViaResource bool `json:"write_via_resource"`
	AdminViaResource bool `json:"admin_via_resource"`

	// Authenticated Scope (Non-Public but exposed to any cloud user)
	AuthenticatedRead  bool `json:"authenticated_read"`
	AuthenticatedWrite bool `json:"authenticated_write"`
	AuthenticatedAdmin bool `json:"authenticated_admin"`

	// Latent Access (Signals that exist but are currently blocked by governance)
	LatentPublicRead bool `json:"latent_public_read"`
	LatentPublicList bool `json:"latent_public_list"`

	// Governance Status
	IdentityExposureBlocked bool `json:"-"` // e.g., BlockPublicPolicy
	ResourceExposureBlocked bool `json:"-"` // e.g., BlockPublicACLs
}

// EffectiveVisibility represents the evaluated domain state used by the
// diagnostic engine to generate findings and classify risk.
type EffectiveVisibility struct {
	Read           bool
	Write          bool
	List           bool
	Delete         bool
	AdminRead      bool
	AdminWrite     bool
	IsLatent       bool // True if the access is blocked by governance
	PrincipalScope kernel.PrincipalScope
}

// IsExposed returns true if any capability is effectively reachable.
func (v EffectiveVisibility) IsExposed() bool {
	return v.Read || v.Write || v.List || v.Delete || v.AdminRead || v.AdminWrite
}

// ToPermission converts the effective flags into a bitmask for logic operations.
func (v EffectiveVisibility) ToPermission() Permission {
	var m Permission
	if v.Read {
		m |= PermRead
	}
	if v.Write {
		m |= PermWrite
	}
	if v.List {
		m |= PermList
	}
	if v.Delete {
		m |= PermDelete
	}
	if v.AdminRead {
		m |= PermMetadataRead
	}
	if v.AdminWrite {
		m |= PermMetadataWrite
	}
	return m
}

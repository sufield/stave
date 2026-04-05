package exposure

import "github.com/sufield/stave/internal/core/kernel"

// VisibilityResult represents the flattened access state of a resource.
// Fields are projected into asset properties for control predicate evaluation.
// The JSON tags are flat (not nested) because YAML control predicates
// reference them as properties.storage.access.public_read etc.
//
// The evaluation pipeline flows: Origins → Governance → Effective.
type VisibilityResult struct {
	// --- Effective permissions (the final answer after governance) ---
	// These are what controls evaluate against. If PublicRead is true,
	// the resource IS publicly readable right now.
	PublicRead   bool `json:"public_read"`
	PublicList   bool `json:"public_list"`
	PublicWrite  bool `json:"public_write"`
	PublicDelete bool `json:"public_delete"`
	PublicAdmin  bool `json:"public_admin"`

	// --- Origin signals (where the exposure comes from, pre-governance) ---
	// Identity = IAM/RBAC policy grants. Resource = bucket policy/ACL grants.
	// Both may be true — the effective permission is the union.
	ReadViaIdentity  bool `json:"read_via_identity"`
	ReadViaResource  bool `json:"read_via_resource"`
	ListViaIdentity  bool `json:"list_via_identity"`
	WriteViaResource bool `json:"write_via_resource"`
	AdminViaResource bool `json:"admin_via_resource"`

	// --- Authenticated scope (any AWS account holder, not just public) ---
	// Nearly as dangerous as public — any of the ~1M AWS accounts can access.
	AuthenticatedRead  bool `json:"authenticated_read"`
	AuthenticatedWrite bool `json:"authenticated_write"`
	AuthenticatedAdmin bool `json:"authenticated_admin"`

	// --- Latent access (blocked by governance but would be exposed without it) ---
	// These are "ticking time bombs" — if someone disables PAB, exposure returns.
	LatentPublicRead bool `json:"latent_public_read"`
	LatentPublicList bool `json:"latent_public_list"`

	// --- Governance overrides (internal, not serialized) ---
	// When true, the corresponding origin signals are suppressed in effective permissions.
	IdentityExposureBlocked bool `json:"-"` // BlockPublicPolicy active
	ResourceExposureBlocked bool `json:"-"` // BlockPublicACLs/IgnorePublicACLs active
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

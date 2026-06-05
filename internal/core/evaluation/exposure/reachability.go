package exposure

import "github.com/sufield/stave/internal/core/kernel"

// ResourceExposure represents the calculated reachability state of a cloud resource.
// It flattens complex IAM and resource-based policies into boolean flags.
//
// The JSON tags are flat to support YAML control predicates that reference
// properties like: storage.access.public_read.
type ResourceExposure struct {
	// --- Effective Exposure (The "Blast Radius") ---
	// These represent the final state after all boundary guardrails
	// (e.g. AWS Block Public Access) have been applied.
	PublicRead   bool `json:"public_read"`
	PublicList   bool `json:"public_list"`
	PublicWrite  bool `json:"public_write"`
	PublicDelete bool `json:"public_delete"`
	PublicAdmin  bool `json:"public_admin"`

	// --- Access Vectors (Grant Sources) ---
	// Identity = IAM/RBAC principal policies.
	// Resource = Bucket/Key/Queue resource-based policies.
	ReadViaIdentity  bool `json:"read_via_identity"`
	ReadViaResource  bool `json:"read_via_resource"`
	ListViaIdentity  bool `json:"list_via_identity"`
	WriteViaResource bool `json:"write_via_resource"`
	AdminViaResource bool `json:"admin_via_resource"`

	// --- Cross-Account / Authenticated Scope ---
	// Represents "Near-Public" exposure where any authenticated cloud
	// tenant can access the resource.
	AuthenticatedRead  bool `json:"authenticated_read"`
	AuthenticatedWrite bool `json:"authenticated_write"`
	AuthenticatedAdmin bool `json:"authenticated_admin"`

	// --- Latent Reachability ("Shadow Exposure") ---
	// Permissions currently suppressed by guardrails that would
	// immediately become active if the guardrail were disabled.
	LatentPublicRead bool `json:"latent_public_read"`
	LatentPublicList bool `json:"latent_public_list"`

	// --- Boundary Guardrails (Internal) ---
	// Tracks if organizational overrides (SCPs, BPA) are currently
	// truncating the effective exposure.
	IdentityGuardrailActive bool `json:"-"`
	ResourceGuardrailActive bool `json:"-"`
}

// IsPubliclyExposed returns true if any access is available to the public internet.
func (e *ResourceExposure) IsPubliclyExposed() bool {
	if e == nil {
		return false
	}
	return e.PublicRead || e.PublicWrite || e.PublicAdmin || e.PublicList || e.PublicDelete
}

// ResolvedAccess represents the final, evaluated entitlement state used by the
// engine to generate findings and classify environmental risk.
type ResolvedAccess struct {
	Read           bool
	Write          bool
	List           bool
	Delete         bool
	AdminRead      bool
	AdminWrite     bool
	IsLatent       bool // True if access is currently suppressed by a guardrail
	PrincipalScope kernel.PrincipalScope
}

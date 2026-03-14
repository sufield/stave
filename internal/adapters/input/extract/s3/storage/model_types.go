package storage

import (
	s3exposure "github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/kernel"
)

type S3Lifecycle struct {
	RulesConfigured                bool `json:"rules_configured"`
	RuleCount                      int  `json:"rule_count"`
	HasExpiration                  bool `json:"has_expiration"`
	HasTransition                  bool `json:"has_transition"`
	MinExpirationDays              int  `json:"min_expiration_days"`
	HasNoncurrentVersionExpiration bool `json:"has_noncurrent_version_expiration"`
}

type S3ObjectLock struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	RetentionDays int    `json:"retention_days"`
}

type S3PrefixExposure struct {
	HasIdentityEvidence   bool                                       `json:"has_identity_evidence"`
	HasResourceEvidence   bool                                       `json:"has_resource_evidence"`
	IdentityReadScopes    []kernel.ObjectPrefix                      `json:"identity_read_scopes"`
	IdentitySourceByScope map[kernel.ObjectPrefix]kernel.StatementID `json:"identity_source_by_scope"`
	IdentityReadBlocked   bool                                       `json:"identity_read_blocked"`
	ResourceReadAll       bool                                       `json:"resource_read_all"`
	ResourceReadBlocked   bool                                       `json:"resource_read_blocked"`
}

// Canonical returns a stable lifecycle model.
func (lc *LifecycleConfig) Canonical() S3Lifecycle {
	if lc == nil {
		return S3Lifecycle{}
	}
	return S3Lifecycle{
		RulesConfigured:                lc.RulesConfigured,
		RuleCount:                      lc.RuleCount,
		HasExpiration:                  lc.HasExpiration,
		HasTransition:                  lc.HasTransition,
		MinExpirationDays:              lc.MinExpirationDays,
		HasNoncurrentVersionExpiration: lc.HasNoncurrentVersionExpiration,
	}
}

// Canonical returns a stable object-lock model.
func (olc *ObjectLockConfig) Canonical() S3ObjectLock {
	if olc == nil {
		return S3ObjectLock{}
	}
	return S3ObjectLock{
		Enabled:       olc.Enabled,
		Mode:          string(olc.Mode),
		RetentionDays: olc.RetentionDays,
	}
}

type BuildModelInput struct {
	Bucket                 *S3Bucket
	AccountPAB             *PublicAccessBlock
	EffectivePAB           PublicAccessBlock
	Access                 s3exposure.BucketAccess
	TransportEnforcesHTTPS bool
}

// S3AccessModel is the unified access projection for S3 buckets.
// All access-related fields live here under the "access" JSON branch.
type S3AccessModel struct {
	// Principal scope & trust boundary (computed by ResolveBucketAccess)
	Scope         kernel.PrincipalScope `json:"scope"`
	TrustBoundary kernel.TrustBoundary  `json:"trust_boundary"`

	// Effective permissions
	PublicRead   bool `json:"public_read"`
	PublicList   bool `json:"public_list"`
	PublicWrite  bool `json:"public_write"`
	PublicDelete bool `json:"public_delete"`
	PublicAdmin  bool `json:"public_admin"`

	// Origin signals
	ReadViaIdentity  bool `json:"read_via_identity"`
	ReadViaResource  bool `json:"read_via_resource"`
	ListViaIdentity  bool `json:"list_via_identity"`
	WriteViaResource bool `json:"write_via_resource"`
	AdminViaResource bool `json:"admin_via_resource"`

	// Authenticated scope
	AuthenticatedRead  bool `json:"authenticated_read"`
	AuthenticatedWrite bool `json:"authenticated_write"`
	AuthenticatedAdmin bool `json:"authenticated_admin"`

	// Latent signals
	LatentPublicRead bool `json:"latent_public_read"`
	LatentPublicList bool `json:"latent_public_list"`

	// ACL full-control grants
	FullControlPublic        bool `json:"has_full_control_public"`
	FullControlAuthenticated bool `json:"has_full_control_authenticated"`

	// Cross-account
	ExternalAccounts   []string `json:"external_accounts"`
	ExternalAccountIDs []string `json:"external_account_ids"`
	HasExternalAccess  bool     `json:"has_external_access"`
	HasExternalWrite   bool     `json:"has_external_write"`
	HasWildcardPolicy  bool     `json:"has_wildcard_policy"`

	// Network scope
	HasIPCondition        bool   `json:"has_ip_condition"`
	HasVPCCondition       bool   `json:"has_vpc_condition"`
	EffectiveNetworkScope string `json:"effective_network_scope"`
}

// S3StorageModel is the projected storage representation of an S3 bucket.
// The JSON field paths (e.g., "access.public_read", "lifecycle.rules_configured",
// "object_lock.enabled") form the projection contract consumed by control YAML
// `field:` expressions. Changes to field names or nesting here break control evaluation.
type S3StorageModel struct {
	// Identity
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`

	// Access
	Access         S3AccessModel    `json:"access"`
	Controls       S3Controls       `json:"controls"`
	PrefixExposure S3PrefixExposure `json:"prefix_exposure"`

	// Security
	Encryption S3Encryption `json:"encryption"`
	Versioning S3Versioning `json:"versioning"`
	Logging    S3Logging    `json:"logging"`
	Website    *S3Website   `json:"website,omitempty"`

	// Operations — value types: controls check eq false on their fields.
	Lifecycle  S3Lifecycle  `json:"lifecycle"`
	ObjectLock S3ObjectLock `json:"object_lock"`

	// Metadata
	Tags map[string]string `json:"tags,omitempty"`
}

type S3Encryption struct {
	AtRestEnabled     bool   `json:"at_rest_enabled"`
	Algorithm         string `json:"algorithm"`
	KMSKeyID          string `json:"kms_key_id"`
	InTransitEnforced bool   `json:"in_transit_enforced"`
}

type S3Versioning struct {
	Enabled          bool `json:"enabled"`
	MFADeleteEnabled bool `json:"mfa_delete_enabled"`
}

type S3Logging struct {
	Enabled      bool   `json:"enabled"`
	TargetBucket string `json:"target_bucket"`
	TargetPrefix string `json:"target_prefix"`
}

type S3Website struct {
	Enabled bool `json:"enabled"`
}

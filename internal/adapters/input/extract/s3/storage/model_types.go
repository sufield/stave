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

// S3StorageModel is the projected storage representation of an S3 bucket.
// The JSON field paths (e.g., "visibility.effective_exposure", "lifecycle.rules_configured",
// "object_lock.enabled") form the projection contract consumed by control YAML
// `field:` expressions. Changes to field names or nesting here break control evaluation.
type S3StorageModel struct {
	// Identity
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`

	// Access & Visibility
	Visibility     s3exposure.VisibilityResult `json:"visibility"`
	ACL            ACLSummary                  `json:"acl"`
	Controls       S3Controls                  `json:"controls"`
	PrefixExposure S3PrefixExposure            `json:"prefix_exposure"`
	Access         CrossAccountSummary         `json:"access"`
	Policy         S3Policy                    `json:"policy"`

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

type ACLSummary struct {
	FullControlPublic        bool `json:"has_full_control_public"`
	FullControlAuthenticated bool `json:"has_full_control_authenticated"`
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

type CrossAccountSummary struct {
	ExternalAccounts   []string `json:"external_accounts"`
	ExternalAccountIDs []string `json:"external_account_ids"`
	HasExternalAccess  bool     `json:"has_external_access"`
	HasExternalWrite   bool     `json:"has_external_write"`
	HasWildcardPolicy  bool     `json:"has_wildcard_policy"`
}

type S3Policy struct {
	HasIPCondition        bool   `json:"has_ip_condition"`
	HasVPCCondition       bool   `json:"has_vpc_condition"`
	EffectiveNetworkScope string `json:"effective_network_scope"`
}

type S3Website struct {
	Enabled bool `json:"enabled"`
}

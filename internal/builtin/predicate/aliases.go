package predicate

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func newBuiltinRegistry() *Registry {
	return &Registry{entries: builtinAliases()}
}

func builtinAliases() map[string]aliasEntry {
	return map[string]aliasEntry{
		// ── Public exposure (composite) ──────────────────────────
		S3IsPublicReadable: {
			Description: "Any path grants public read access (direct, identity-based, or resource-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.read_via_identity"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.read_via_resource"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3IsPublicWritable: {
			Description: "Any path grants public write access (direct or resource-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_write"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.write_via_resource"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3IsPublicListable: {
			Description: "Any path grants public list access (direct or identity-based)",
			Category:    CategoryPublicExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.list_via_identity"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Latent exposure (masked by public access block only) ─
		S3LatentPublicRead: {
			Description: "Latent public read access masked only by public access block",
			Category:    CategoryLatentExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.latent_public_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3LatentPublicList: {
			Description: "Latent public list access masked only by public access block",
			Category:    CategoryLatentExposure,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.latent_public_list"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Authenticated-users access ───────────────────────────
		S3AuthenticatedUsersRead: {
			Description: "Read access granted to all authenticated AWS users",
			Category:    CategoryAuthenticatedAccess,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_read"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3AuthenticatedUsersWrite: {
			Description: "Write access granted to all authenticated AWS users",
			Category:    CategoryAuthenticatedAccess,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_write"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Admin grants ─────────────────────────────────────────
		S3ACLWritable: {
			Description: "ACL grants write-ACP to public or all authenticated users",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.authenticated_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3ACLReadableByPublic: {
			Description: "ACL read-ACP granted to the public",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.public_admin"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},
		S3HasFullControlGrant: {
			Description: "FULL_CONTROL grant to public or all authenticated users",
			Category:    CategoryAdminGrants,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.access.has_full_control_public"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.access.has_full_control_authenticated"), Op: predicate.OpEq, Value: policy.Bool(true)},
				},
			},
		},

		// ── Encryption ───────────────────────────────────────────
		S3EncryptionAtRestDisabled: {
			Description: "Server-side encryption at rest is not enabled",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.at_rest_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3EncryptionInTransitNotEnforced: {
			Description: "Bucket policy does not enforce TLS for data in transit",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.in_transit_enforced"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3NotUsingKMSCMK: {
			Description: "Encryption does not use a customer-managed KMS key",
			Category:    CategoryEncryption,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.encryption.algorithm"), Op: predicate.OpNe, Value: policy.Str("aws:kms")},
					{Field: predicate.NewFieldPath("properties.storage.encryption.kms_key_id"), Op: predicate.OpEq, Value: policy.Str("")},
				},
			},
		},

		// ── Logging ──────────────────────────────────────────────
		S3LoggingDisabled: {
			Description: "Server access logging is not enabled",
			Category:    CategoryLogging,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.logging.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Versioning ───────────────────────────────────────────
		S3VersioningDisabled: {
			Description: "Bucket versioning is not enabled",
			Category:    CategoryVersioning,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.versioning.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3MFADeleteDisabled: {
			Description: "MFA delete protection is not enabled",
			Category:    CategoryVersioning,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.versioning.mfa_delete_enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Controls ─────────────────────────────────────────────
		S3PublicAccessBlockDisabled: {
			Description: "S3 public access block is not fully enabled",
			Category:    CategoryControls,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.controls.public_access_fully_blocked"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},

		// ── Object lock ──────────────────────────────────────────
		S3ObjectLockDisabled: {
			Description: "Object Lock is not enabled on the bucket",
			Category:    CategoryObjectLock,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.object_lock.enabled"), Op: predicate.OpEq, Value: policy.Bool(false)},
				},
			},
		},
		S3ObjectLockNotComplianceMode: {
			Description: "Object Lock is enabled but not in COMPLIANCE mode",
			Category:    CategoryObjectLock,
			Service:     "s3",
			Predicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.object_lock.enabled"), Op: predicate.OpEq, Value: policy.Bool(true)},
					{Field: predicate.NewFieldPath("properties.storage.object_lock.mode"), Op: predicate.OpNe, Value: policy.Str("COMPLIANCE")},
				},
			},
		},
	}
}

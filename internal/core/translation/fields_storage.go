package translation

func storageFields() FieldRegistry {
	return FieldRegistry{
		// --- storage: access control ---
		"storage.access.public_read":                    "the bucket allows anonymous read",
		"storage.access.public_list":                    "the bucket allows anonymous list",
		"storage.access.public_write":                   "the bucket allows anonymous write",
		"storage.access.public_admin":                   "the bucket allows anonymous write-ACP",
		"storage.access.authenticated_read":             "the bucket allows authenticated-users read",
		"storage.access.authenticated_write":            "the bucket allows authenticated-users write",
		"storage.access.authenticated_admin":            "the bucket allows authenticated-users write-ACP",
		"storage.access.has_wildcard_principal":         "the bucket policy grants to Principal \"*\"",
		"storage.access.has_external_write":             "the bucket grants write to an external account",
		"storage.access.has_full_control_public":        "the bucket grants FULL_CONTROL to AllUsers",
		"storage.access.has_full_control_authenticated": "the bucket grants FULL_CONTROL to AuthenticatedUsers",
		"storage.access.external_account_ids":           "the bucket policy lists external accounts",
		"storage.access.read_via_resource":              "the bucket policy grants read to a public principal",
		"storage.access.write_via_resource":             "the bucket policy grants write to a public principal",
		"storage.access.read_via_identity":              "an IAM identity has read access to the bucket",
		"storage.access.list_via_identity":              "an IAM identity has list access to the bucket",
		"storage.access.latent_public_read":             "the bucket would be publicly readable if PAB were removed",
		"storage.access.latent_public_list":             "the bucket would be publicly listable if PAB were removed",
		"storage.access.policy_has_scoping_condition":   "every non-narrow Allow carries a scoping Condition",
		"storage.access.policy_is_effectively_public":   "the bucket policy is effectively public per AWS PolicyStatus",
		// `storage.policy_json` is the raw resource-based policy text.
		// Empty string means no policy is attached; under AWS implicit
		// deny, that bucket denies every request unless an identity-
		// or session-policy explicitly grants access. The absence is a
		// posture signal (CTL.S3.POLICY.EXISTS.001), not an exposure
		// signal — exposure is determined by the policy *content* via
		// the access.* booleans below.
		//
		// Three-state policy posture is encoded by two booleans rather
		// than a single enum:
		//   absent      → policy_json == ""
		//   scoped      → policy_json != "" AND policy_is_effectively_public == false
		//                 AND (policy_has_scoping_condition is null OR true)
		//   overly_broad → policy_json != "" AND
		//                  (policy_is_effectively_public == true OR
		//                   policy_has_scoping_condition == false)
		// A consolidating `policy_state` enum was considered and rejected:
		// the two-boolean form is already the producer's wire shape, the
		// controls read it that way, and adding a third derived field
		// would create a consistency hazard (producer must keep all three
		// in lockstep) for a labeling win.
		"storage.policy_json":                    "the bucket's resource-based policy text (empty = no policy attached, AWS implicit deny applies)",
		"storage.access.has_vpc_condition":       "a VPC-scoping Condition is present (aws:SourceVpc / aws:SourceVpce)",
		"storage.access.has_ip_condition":        "an IP-scoping Condition is present (aws:SourceIp with a fixed CIDR)",
		"storage.access.effective_network_scope": "the bucket's effective network scope",
		"storage.access.exposes_bucket_policy":   "the bucket policy grants s3:GetBucketPolicy to anonymous callers",

		// --- storage: PAB (bucket level) ---
		"storage.controls.public_access_fully_blocked":                 "all four Public Access Block flags are enabled",
		"storage.controls.account_public_access_fully_blocked":         "all four account-level Public Access Block flags are enabled",
		"storage.controls.public_access_block.block_public_acls":       "BlockPublicAcls is enabled",
		"storage.controls.public_access_block.ignore_public_acls":      "IgnorePublicAcls is enabled",
		"storage.controls.public_access_block.block_public_policy":     "BlockPublicPolicy is enabled",
		"storage.controls.public_access_block.restrict_public_buckets": "RestrictPublicBuckets is enabled",

		// --- storage: access-point level (overlay on bucket) ---
		"storage.public_access_block.block_public_acls":       "the Access Point BlockPublicAcls flag is enabled",
		"storage.public_access_block.ignore_public_acls":      "the Access Point IgnorePublicAcls flag is enabled",
		"storage.public_access_block.block_public_policy":     "the Access Point BlockPublicPolicy flag is enabled",
		"storage.public_access_block.restrict_public_buckets": "the Access Point RestrictPublicBuckets flag is enabled",
		"storage.public_access_fully_blocked":                 "all four Access Point PAB flags are enabled",
		"storage.mrap_policy_is_public":                       "the Multi-Region Access Point policy is public",
		"storage.mrap_public_access_blocked":                  "the Multi-Region Access Point blocks public access",

		// --- storage: encryption ---
		"storage.encryption.at_rest_enabled":     "server-side encryption at rest is enabled",
		"storage.encryption.in_transit_enforced": "HTTPS-only (aws:SecureTransport) is enforced",
		"storage.encryption.algorithm":           "the encryption algorithm",
		"storage.encryption.kms_key_id":          "the KMS key ARN used for encryption",

		// --- storage: logging / versioning / object lock / lifecycle ---
		"storage.logging.enabled":               "access logging is enabled",
		"storage.versioning.enabled":            "versioning is enabled",
		"storage.versioning.mfa_delete_enabled": "MFA Delete is enabled",
		"storage.object_lock.enabled":           "Object Lock is enabled",
		"storage.object_lock.mode":              "Object Lock retention mode",
		"storage.object_lock.retention_days":    "Object Lock retention days",
		"storage.object_ownership.rule":         "the Object Ownership rule",
		"storage.lifecycle.rules_configured":    "lifecycle rules are configured",
		"storage.lifecycle.has_expiration":      "a lifecycle expiration rule is configured",
		"storage.lifecycle.min_expiration_days": "the minimum lifecycle expiration in days",

		// --- storage: tags + tenancy ---
		"storage.tags.data-classification":  "the bucket's data-classification tag",
		"storage.tags.data-retention":       "the bucket's data-retention tag",
		"storage.tags.backup":               "the bucket's backup tag",
		"storage.tags.compliance":           "the bucket's compliance tag",
		"storage.tags.public_list_intended": "the bucket's public-list-intended tag",
		"storage.tags.tenant_mode":          "the bucket's tenant_mode tag",
		"storage.tags.tenant_prefix":        "the bucket's tenant_prefix tag",

		// --- storage: CDN coupling ---
		"storage.cdn_access.bucket_policy_grants_cloudfront": "the bucket policy grants the CloudFront service principal",
		"storage.cdn_access.cloudfront_oai.enabled":          "a legacy CloudFront Origin Access Identity is attached",

		// --- storage: access grants + s3 upload ---
		"storage.access_grants.instance_exists":          "an S3 Access Grants instance exists for the account",
		"storage.access_grants.identity_center_attached": "Identity Center is attached to the Access Grants instance",
		"storage.access_grants.has_broad_write_grant":    "an Access Grants entry has a broad write grant",
		"s3_upload.operation":                            "the S3 upload operation",
		"s3_upload.allowed_key_mode":                     "the S3 upload key-allowlist mode",
		"s3_upload.content_type_restricted":              "content-type is restricted on the S3 upload",
		"s3_ref.bucket_exists":                           "the referenced S3 bucket exists",
		"s3_ref.bucket_owned":                            "the referenced S3 bucket is owned by the account",
	}
}

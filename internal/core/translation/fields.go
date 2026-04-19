package translation

// DefaultFieldRegistry is the plain-language translation table for
// observation field paths that appear in shipped findings'
// ReasoningTrace output. See docs/product/metrics.md § Metric 5.
//
// Entries are hand-maintained. When a new control lands that reads
// a path not present here, the text writer falls back to the raw
// DSL path and the gap shows up as an opaque line in the Reasoning
// block — the signal to extend this map.
//
// Coverage target: the paths actually emitted into findings'
// ReasoningTrace (not the full 713-path contract surface). The set
// is dominated by a small number of high-signal paths; the
// long-tail extends here incrementally.
//
// Inventory source: `grep "observation_key" testdata/e2e/*/
// expected.out.json | sort -u`. Re-run when adding controls that
// emit new paths.
var DefaultFieldRegistry = FieldRegistry{
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
	"storage.access.has_vpc_condition":              "a VPC-scoping Condition is present (aws:SourceVpc / aws:SourceVpce)",
	"storage.access.has_ip_condition":               "an IP-scoping Condition is present (aws:SourceIp with a fixed CIDR)",
	"storage.access.effective_network_scope":        "the bucket's effective network scope",
	"storage.access.exposes_bucket_policy":          "the bucket policy grants s3:GetBucketPolicy to anonymous callers",

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

	// --- identity / IAM ---
	"identity.auth.mfa_enforced":       "MFA is enforced for this identity",
	"identity.root.mfa_enabled":        "MFA is enabled on the root account",
	"identity.root.has_access_keys":    "the root account has access keys",
	"identity.nep.has_escalation_path": "a net-effective privilege escalation path exists for this identity",
	"identity.nep.is_admin":            "this identity has net-effective admin privileges",
	"identities":                       "the observation's identities list",

	// --- cryptography (KMS) ---
	"cryptography.policy.has_wildcard_principal": "the KMS key policy grants to Principal \"*\"",

	// --- database / RDS ---
	"database.access.publicly_accessible":        "the database is publicly accessible",
	"database.access.iam_authentication_enabled": "IAM database authentication is enabled",
	"database.access.multi_az":                   "the database is deployed Multi-AZ",
	"database.encryption.storage_encrypted":      "storage-at-rest encryption is enabled on the database",
	"database.encryption.require_ssl":            "the database requires SSL connections",
	"database.encryption.sse_type":               "the database SSE type",
	"database.backup.enabled":                    "automated backups are enabled on the database",
	"database.logging.audit_log_enabled":         "database audit logging is enabled",

	// --- compute (Lambda / EC2 / ECS) ---
	"compute.execution_role.is_overprivileged": "the compute execution role is over-privileged",
	"compute.encryption.ebs_encrypted":         "EBS volumes are encrypted",
	"compute.network.has_public_ip":            "the compute resource has a public IP",

	// --- network ---
	"network.flow_log.enabled": "VPC Flow Logs are enabled",

	// --- cache / messaging / API / load balancer / audit / availability / replication ---
	"cache.encryption.in_transit_enabled":            "cache in-transit encryption is enabled",
	"cache.kind":                                     "the cache resource kind",
	"messaging.encryption.encrypted":                 "messaging encryption is enabled",
	"api.encryption.tls_enforced":                    "API Gateway TLS is enforced",
	"loadbalancer.encryption.tls_1_2_or_higher":      "the load balancer uses TLS 1.2 or higher",
	"loadbalancer.encryption.http_to_https_redirect": "the load balancer redirects HTTP to HTTPS",
	"loadbalancer.availability.cross_zone_enabled":   "cross-zone load balancing is enabled",
	"loadbalancer.logging.access_log_enabled":        "load balancer access logging is enabled",
	"audit_trail.encryption.encrypted":               "the audit trail is encrypted",
	"audit_trail.multi_region_enabled":               "the audit trail is multi-region",
	"audit_trail.log_file_validation_enabled":        "audit trail log file validation is enabled",
	"availability.multi_az":                          "the resource is deployed Multi-AZ",
	"availability.kind":                              "the availability resource kind",
	"replication.cross_region_enabled":               "cross-region replication is enabled",
	"replication.kind":                               "the replication resource kind",

	// --- secret / compliance / log group / DNS / backup ---
	"secret.access.rotation_enabled":         "secret rotation is enabled",
	"secret.encryption.customer_managed_key": "the secret is encrypted with a customer-managed key",
	"compliance.has_active_rules":            "compliance service has active rules",
	"compliance.recording_enabled":           "compliance recording is enabled",
	"log_group.has_retention_policy":         "the log group has a retention policy",
	"log_group.kind":                         "the log group resource kind",
	"dns.target_exists":                      "the DNS record's target exists",
	"dns.target_owned":                       "the DNS record's target is owned by the account",
	"backup.has_backup":                      "the resource has a backup configured",

	// --- synthetic / derived predicate-emitted keys ---
	"binds_to_cluster_admin":          "the role binds to cluster-admin",
	"binds_to_system_unauthenticated": "the role binds to system:unauthenticated",
	"exposure_source":                 "the exposure source",
	"protected_prefix":                "the protected prefix",
	"overlap_with":                    "the overlapping prefix",
	"public":                          "the resource is public",
	"type":                            "the asset type",
}

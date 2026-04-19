# Storage Domain

Contract fields for object storage services — S3 buckets, GCS buckets, and
single-region S3 Access Points. Namespace prefix: `storage.*`. Also
covers `s3_ref.*` (bucket reference / takeover detection) and
`s3_upload.*` (upload policy scope).

Part of the [observation contract](README.md).

## Field dictionary

### Access control

| Field | Type | Description |
|-------|------|-------------|
| `storage.access.public_read` | bool | Public read access |
| `storage.access.public_read_scope` | string/null | Scope of any public-read grant in the bucket policy: `"bucket"` (Resource is the bucket itself or `bucket/*`), `"prefix"` (Resource is a `bucket/prefix/*` pattern narrower than the whole bucket), `"object"` (Resource names one or more specific object keys, e.g. `bucket/backup.xlsx`), or `"mixed"` (a single Allow statement contains Resource entries spanning more than one of the above). `null` or omitted when `public_read = false` — nothing to scope. |
| `storage.access.public_list` | bool | Public list access |
| `storage.access.public_write` | bool | Public write access |
| `storage.access.read_via_identity` | bool | Read via identity-based policy |
| `storage.access.list_via_identity` | bool | List via identity-based policy |
| `storage.access.write_via_resource` | bool | Write via resource-based policy |
| `storage.access.read_via_resource` | bool | Read via resource-based policy |
| `storage.access.public_admin` | bool | Public ACL write-ACP |
| `storage.access.authenticated_admin` | bool | Authenticated-users ACL write-ACP |
| `storage.access.has_full_control_public` | bool | FULL_CONTROL grant to public |
| `storage.access.has_full_control_authenticated` | bool | FULL_CONTROL grant to authenticated users |
| `storage.access.authenticated_read` | bool | Authenticated-users read |
| `storage.access.authenticated_write` | bool | Authenticated-users write |
| `storage.access.external_account_ids` | array | External AWS account IDs with access |
| `storage.access.has_external_write` | bool | External accounts have write access |
| `storage.access.has_wildcard_principal` | bool | Any Allow statement's `Principal` is `"*"` or `{"AWS": "*"}`. Conditions do not affect this value. |
| `storage.access.policy_is_effectively_public` | bool | Bucket policy is public per AWS `PolicyStatus.IsPublic` rules. Restricting Conditions (`aws:PrincipalOrgID`, `aws:SourceVpc`, `aws:SourceIp` with CIDR, `aws:SourceArn`, all with fixed values) make this `false` even when `has_wildcard_principal` is `true`. |
| `storage.access.policy_has_scoping_condition` | bool/null | `true` when every Allow statement with a non-narrow principal (`Principal: "*"`, `Principal: {"AWS": "*"}`, or an Allow with no `Principal` block) carries at least one scoping Condition with a fixed value — `aws:PrincipalOrgID`, `aws:SourceVpc`, `aws:SourceIp` with a fixed CIDR, or `aws:SourceArn`. `false` when any such Allow statement exists without any scoping Condition. `null` (or omitted) when the bucket has no policy, or the policy has no Allow statement with a non-narrow principal — there is nothing to scope. |
| `storage.access.exposes_bucket_policy` | bool | Bucket policy grants `s3:GetBucketPolicy` to an anonymous or wildcard principal |
| `storage.access.latent_public_read` | bool | Read would be public if PAB removed |
| `storage.access.latent_public_list` | bool | List would be public if PAB removed |
| `storage.access.has_vpc_condition` | bool | `true` when at least one Allow statement in the bucket policy carries a VPC-scoping Condition with a fixed value — `aws:SourceVpc` or `aws:SourceVpce`. `false` when no Allow statement carries such a Condition, including when the bucket has no policy at all. Consumed by `CTL.S3.NETWORK.VPC.001`, which fires when this and `has_ip_condition` are both `false`. Extractors must emit this field on every bucket; the predicate short-circuits to no-fire on a missing field. |
| `storage.access.has_ip_condition` | bool | `true` when at least one Allow statement in the bucket policy carries an IP-scoping Condition with a fixed CIDR — `aws:SourceIp` with a concrete value (not `0.0.0.0/0`). `false` when no Allow statement carries such a Condition, including when the bucket has no policy at all. Consumed by `CTL.S3.NETWORK.VPC.001`, which fires when this and `has_vpc_condition` are both `false`. Extractors must emit this field on every bucket; the predicate short-circuits to no-fire on a missing field. |
| `storage.access.effective_network_scope` | string | Network restriction scope |

### CDN access (CloudFront coupling)

| Field | Type | Description |
|-------|------|-------------|
| `storage.cdn_access.bucket_policy_grants_cloudfront` | bool | Bucket policy grants access to `cloudfront.amazonaws.com` service principal |
| `storage.cdn_access.cloudfront_oai.enabled` | bool | Legacy Origin Access Identity is attached to a CloudFront distribution fronting this bucket |
| `storage.cdn_access.cloudfront_oac.enabled` | bool | Origin Access Control is attached to a CloudFront distribution fronting this bucket |
| `storage.cdn_access.is_cloudfront_origin` | bool | Any CloudFront distribution in the account has this bucket as an origin. Independent of whether the bucket policy also grants the CloudFront service principal. |

### Controls and settings

| Field | Type | Description |
|-------|------|-------------|
| `storage.controls.public_access_fully_blocked` | bool | All PAB settings block public access |
| `storage.controls.public_access_block.block_public_acls` | bool | S3 Block Public ACLs |
| `storage.controls.public_access_block.ignore_public_acls` | bool | S3 Ignore Public ACLs |
| `storage.controls.public_access_block.block_public_policy` | bool | S3 Block Public Policy |
| `storage.controls.public_access_block.restrict_public_buckets` | bool | S3 Restrict Public Buckets |

### Encryption

| Field | Type | Description |
|-------|------|-------------|
| `storage.encryption.at_rest_enabled` | bool | Server-side encryption enabled |
| `storage.encryption.in_transit_enforced` | bool | HTTPS-only policy enforced |
| `storage.encryption.algorithm` | string | Algorithm (`"aws:kms"`, `"AES256"`) |
| `storage.encryption.kms_key_id` | string | KMS key ARN (if applicable) |

### Versioning

| Field | Type | Description |
|-------|------|-------------|
| `storage.versioning.enabled` | bool | Versioning enabled |
| `storage.versioning.mfa_delete_enabled` | bool | MFA delete required |

### Logging

| Field | Type | Description |
|-------|------|-------------|
| `storage.logging.enabled` | bool | Access logging enabled |

### Object lock

| Field | Type | Description |
|-------|------|-------------|
| `storage.object_lock.enabled` | bool | Object lock enabled |
| `storage.object_lock.mode` | string | Lock mode (`"COMPLIANCE"`, `"GOVERNANCE"`) |
| `storage.object_lock.retention_days` | integer | Retention period in days |

### Website

| Field | Type | Description |
|-------|------|-------------|
| `storage.website.enabled` | bool | Static website hosting enabled |

### Content

| Field | Type | Description |
|-------|------|-------------|
| `storage.content.exposed_repo_artifacts` | bool | Repository artifacts publicly exposed |

### Lifecycle

| Field | Type | Description |
|-------|------|-------------|
| `storage.lifecycle.rules_configured` | bool | Lifecycle rules present |
| `storage.lifecycle.has_expiration` | bool | At least one expiration rule |
| `storage.lifecycle.min_expiration_days` | integer | Shortest expiration period |

### Tags (data governance)

| Field | Type | Description |
|-------|------|-------------|
| `storage.tags.data-classification` | string | `"phi"`, `"pii"`, `"confidential"` |
| `storage.tags.data-retention` | string | Retention policy tag |
| `storage.tags.compliance` | string | Compliance framework tag |
| `storage.tags.backup` | string | Backup policy tag |
| `storage.tags.public_list_intended` | string | Declares intentional public listing |
| `storage.tags.tenant_mode` | string | Multi-tenancy mode (`"shared"`) |
| `storage.tags.tenant_prefix` | string | Tenant prefix scope |

### CDN and origin (resource takeover)

| Field | Type | Description |
|-------|------|-------------|
| `cdn.kind` | string | CDN type |
| `cdn.origins_has_dangling_s3` | bool | Origin points to non-existent S3 bucket |

### Cross-origin resource sharing (CORS)

Captured from `aws s3api get-bucket-cors`. `configured` distinguishes
a bucket with no CORS config (`NoSuchCORSConfiguration`) from one with
an empty or populated CORS config. The wildcard-origin boolean is
precomputed from the raw `CORSRules` array so predicates can evaluate
it directly. See the cross-service CORS namespace section below for
API Gateway, CloudFront, and Lambda Function URL equivalents.

| Field | Type | Description |
|-------|------|-------------|
| `storage.cors.configured` | bool | Bucket has any CORS configuration |
| `storage.cors.allows_wildcard_origin` | bool | Any rule has `"*"` in `AllowedOrigins` |

### Bucket reference checks

| Field | Type | Description |
|-------|------|-------------|
| `s3_ref.bucket_exists` | bool | Referenced bucket exists |
| `s3_ref.bucket_owned` | bool | Referenced bucket is owned by this account |

### Upload and write scope

| Field | Type | Description |
|-------|------|-------------|
| `s3_upload.operation` | string | Upload operation type |
| `s3_upload.allowed_key_mode` | string | Key restriction mode |
| `s3_upload.content_type_restricted` | bool | Content-type restrictions enforced |

### Safety provability

| Field | Type | Description |
|-------|------|-------------|
| `safety_provable` | bool | Whether bucket safety can be proven from observation data |

### Single-region S3 Access Point (`aws_s3_access_point`)

Access Points are named endpoints attached to a single bucket. Each Access
Point carries its own Public Access Block settings and its own resource policy,
both evaluated independently of the parent bucket's controls. An Access Point
can therefore expose a bucket that is itself hardened, or delegate a narrower
slice of a broadly-configured bucket. Single-region Access Points are a
separate resource kind from Multi-Region Access Points (MRAPs) — MRAP facts
are attached to the bucket asset as `storage.multi_region_access_points[]`;
single-region Access Points are top-level `aws_s3_access_point` assets with
`storage.kind = "access_point"`.

| Field | Type | Description |
|-------|------|-------------|
| `storage.kind` | string | `"access_point"` — discriminator |
| `storage.name` | string | Access Point name |
| `storage.bucket_name` | string | Name of the parent bucket the Access Point delegates to |
| `storage.network_origin` | string | `"vpc"` or `"internet"` — the reachability surface of the endpoint |
| `storage.vpc_id` | string/null | VPC identifier when `network_origin = "vpc"`; `null` or omitted for `"internet"` |
| `storage.alias` | string | Access Point DNS alias (e.g., `my-ap-xxxx.s3-accesspoint.us-east-1.amazonaws.com`) |
| `storage.public_access_block.block_public_acls` | bool | Access Point PAB: BlockPublicAcls |
| `storage.public_access_block.ignore_public_acls` | bool | Access Point PAB: IgnorePublicAcls |
| `storage.public_access_block.block_public_policy` | bool | Access Point PAB: BlockPublicPolicy |
| `storage.public_access_block.restrict_public_buckets` | bool | Access Point PAB: RestrictPublicBuckets |
| `storage.public_access_fully_blocked` | bool | Derived: all four `public_access_block.*` flags are `true` |
| `storage.policy_is_public` | bool | Access Point policy evaluates as public under AWS `PolicyStatus.IsPublic` semantics — a wildcard principal without a restricting Condition on `aws:SourceVpc`, `aws:SourceVpce`, `aws:PrincipalOrgID`, `aws:PrincipalArn`, or a narrow `aws:SourceIp`. Mirrors the MRAP field `storage.mrap_policy_is_public`. |

---

## GCS Domain (storage.*)

GCS uses the same `storage.*` namespace as S3 where semantics align.
GCP-specific properties use fields that don't exist in the S3 contract.

### Bucket-level (`gcp_gcs_bucket`)

| Field | Type | Description |
|-------|------|-------------|
| `storage.kind` | string | `"bucket"` — discriminator (shared with S3) |
| `storage.access.public_read` | bool | Public read via IAM bindings (allUsers) |
| `storage.access.public_list` | bool | Public list via IAM bindings |
| `storage.access.public_write` | bool | Public write via IAM bindings |
| `storage.controls.uniform_access_enabled` | bool | Uniform bucket-level access (GCP-specific) |
| `storage.encryption.at_rest_enabled` | bool | Encryption enabled (always true for GCS) |
| `storage.encryption.cmek_enabled` | bool | Customer-managed key via Cloud KMS (GCP-specific) |
| `storage.logging.enabled` | bool | Access logging enabled |
| `storage.versioning.enabled` | bool | Object versioning enabled |

**Cross-cloud shared fields:** `storage.kind`, `storage.access.public_read`,
`storage.access.public_list`, `storage.encryption.at_rest_enabled`,
`storage.logging.enabled`, `storage.versioning.enabled`.

**GCP-specific fields:** `storage.controls.uniform_access_enabled`,
`storage.encryption.cmek_enabled`.

---


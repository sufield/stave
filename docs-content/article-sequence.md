# Article Sequence: S3 Configuration Safety

44 articles. Each one fixes exactly one issue using exactly one control.

Every article follows the same format:
1. One-sentence description of the misconfiguration
2. The raw AWS CLI command and its output
3. A `jq` command to extract into a Stave observation (`obs.v0.1`)
4. `stave apply` to detect the violation
5. The fixed AWS CLI output
6. `stave verify --before ... --after ...` to confirm remediation

Articles are ordered by complexity within each level.

---

## Sequence

| # | Control | Name | Severity | AWS CLI Command | Level |
|---|---------|------|----------|----------------|-------|
| 1 | CTL.S3.PUBLIC.001 | No Public S3 Bucket Read | critical | `get-bucket-policy` | Beginner |
| 2 | CTL.S3.CONTROLS.001 | Public Access Block Must Be Enabled | high | `get-public-access-block` | Beginner |
| 3 | CTL.S3.ENCRYPT.001 | Encryption at Rest Required | high | `get-bucket-encryption` | Beginner |
| 4 | CTL.S3.LOG.001 | Access Logging Required | medium | `get-bucket-logging` | Beginner |
| 5 | CTL.S3.VERSION.001 | Versioning Required | medium | `get-bucket-versioning` | Beginner |
| 6 | CTL.S3.VERSION.002 | Backup Buckets Must Have MFA Delete Enabled | medium | `get-bucket-versioning` | Beginner |
| 7 | CTL.S3.GOVERNANCE.001 | Data Classification Tag Required | low | `get-bucket-tagging` | Beginner |
| 8 | CTL.S3.INCOMPLETE.001 | Complete Data Required for Safety Assessment | low | multiple | Beginner |
| 9 | CTL.S3.ENCRYPT.002 | Transport Encryption Required | high | `get-bucket-policy` | Intermediate |
| 10 | CTL.S3.PUBLIC.007 | No Public Read via Policy | critical | `get-bucket-policy` | Intermediate |
| 11 | CTL.S3.PUBLIC.008 | No Public List via Policy | critical | `get-bucket-policy` | Intermediate |
| 12 | CTL.S3.PUBLIC.003 | No Public Write Access | critical | `get-bucket-policy` | Intermediate |
| 13 | CTL.S3.ACCESS.002 | No Wildcard Action Policies | high | `get-bucket-policy` | Intermediate |
| 14 | CTL.S3.ACCESS.003 | No External Write Access | high | `get-bucket-policy` | Intermediate |
| 15 | CTL.S3.NETWORK.001 | Public-Principal Policies Must Have Network Conditions | high | `get-bucket-policy` | Intermediate |
| 16 | CTL.S3.PUBLIC.004 | No Public Read via ACL | medium | `get-bucket-acl` | Intermediate |
| 17 | CTL.S3.ACL.WRITE.001 | No Public Write via ACL | critical | `get-bucket-acl` | Intermediate |
| 18 | CTL.S3.ACL.FULLCONTROL.001 | No FULL_CONTROL ACL Grants to Public | critical | `get-bucket-acl` | Intermediate |
| 19 | CTL.S3.ACL.RECON.001 | No Public ACL Readability | high | `get-bucket-acl` | Intermediate |
| 20 | CTL.S3.ACL.ESCALATION.001 | No Public ACL Modification | high | `get-bucket-acl` | Intermediate |
| 21 | CTL.S3.AUTH.READ.001 | No Authenticated-Users Read Access | high | `get-bucket-acl` | Intermediate |
| 22 | CTL.S3.AUTH.WRITE.001 | No Authenticated-Users Write Access | high | `get-bucket-acl` | Intermediate |
| 23 | CTL.S3.PUBLIC.LIST.001 | No Public S3 Bucket Listing | high | `get-bucket-policy`, `get-bucket-acl` | Intermediate |
| 24 | CTL.S3.PUBLIC.LIST.002 | Anonymous S3 Listing Must Be Explicitly Intended | high | `get-bucket-policy`, `get-bucket-acl` | Intermediate |
| 25 | CTL.S3.PUBLIC.005 | No Latent Public Read Exposure | medium | `get-bucket-policy`, `get-public-access-block` | Intermediate |
| 26 | CTL.S3.PUBLIC.006 | No Latent Public Bucket Listing | critical | `get-bucket-policy`, `get-public-access-block` | Intermediate |
| 27 | CTL.S3.ACCESS.001 | No Unauthorized Cross-Account Access | high | `get-bucket-policy` | Intermediate |
| 28 | CTL.S3.PUBLIC.002 | No Public S3 Buckets With Sensitive Data | critical | `get-bucket-policy`, `get-bucket-tagging` | Intermediate |
| 29 | CTL.S3.PUBLIC.PREFIX.001 | Protected Prefixes Must Not Be Publicly Readable | high | `get-bucket-policy`, `get-bucket-acl` | Intermediate |
| 30 | CTL.S3.ENCRYPT.003 | PHI Buckets Must Use SSE-KMS with Customer-Managed Key | high | `get-bucket-encryption`, `get-bucket-tagging` | Advanced |
| 31 | CTL.S3.ENCRYPT.004 | Sensitive Data Requires KMS Encryption | high | `get-bucket-encryption`, `get-bucket-tagging` | Advanced |
| 32 | CTL.S3.LIFECYCLE.001 | Retention-Tagged Buckets Must Have Lifecycle Rules | medium | `get-bucket-lifecycle-configuration`, `get-bucket-tagging` | Advanced |
| 33 | CTL.S3.LIFECYCLE.002 | PHI Buckets Must Not Expire Data Before Minimum Retention | medium | `get-bucket-lifecycle-configuration`, `get-bucket-tagging` | Advanced |
| 34 | CTL.S3.LOCK.001 | Compliance-Tagged Buckets Must Have Object Lock Enabled | medium | `get-object-lock-configuration`, `get-bucket-tagging` | Advanced |
| 35 | CTL.S3.LOCK.002 | PHI Buckets Must Use COMPLIANCE Mode Object Lock | medium | `get-object-lock-configuration`, `get-bucket-tagging` | Advanced |
| 36 | CTL.S3.LOCK.003 | PHI Object Lock Retention Must Meet Minimum Period | medium | `get-object-lock-configuration`, `get-bucket-tagging` | Advanced |
| 37 | CTL.S3.WEBSITE.PUBLIC.001 | No Public Website Hosting with Public Read | critical | `get-bucket-website`, `get-bucket-policy` | Advanced |
| 38 | CTL.S3.REPO.ARTIFACT.001 | Public Buckets Must Not Expose VCS Artifacts | medium | `list-objects-v2`, `get-bucket-policy` | Advanced |
| 39 | CTL.S3.WRITE.SCOPE.001 | S3 Signed Upload Must Bind To Exact Object Key | high | `get-bucket-policy` | Advanced |
| 40 | CTL.S3.WRITE.CONTENT.001 | S3 Signed Upload Must Restrict Content Types | high | `get-bucket-policy`, `get-bucket-cors` | Advanced |
| 41 | CTL.S3.TENANT.ISOLATION.001 | Shared-Bucket Tenant Isolation Must Enforce Prefix | high | `get-bucket-policy` | Advanced |
| 42 | CTL.S3.BUCKET.TAKEOVER.001 | Referenced S3 Buckets Must Exist And Be Owned | critical | `list-buckets`, CloudFront `list-distributions` | Advanced |
| 43 | CTL.S3.DANGLING.ORIGIN.001 | CDN S3 Origins Must Not Be Dangling | high | `list-buckets`, CloudFront `list-distributions` | Advanced |
| 44 | — | Full Hardening Audit | all | All commands combined | Capstone |

---

## Progression

| Level | Articles | Reader Learns |
|-------|----------|--------------|
| **Beginner** (1-8) | One CLI command, one control, direct field mapping | Basic jq extraction, `stave apply`, `stave verify`, observation schema |
| **Intermediate** (9-29) | Policy/ACL parsing with jq, tag-gated controls, control parameters | Conditional jq logic, multi-field observations, `params` customization |
| **Advanced** (30-43) | Compliance-driven controls, cross-service data, upload/lifecycle/lock | Tag-conditional evaluation, cross-service observations, custom extractors |
| **Capstone** (44) | All 43 controls against one bucket | Complete extractor script, full audit workflow |

---

## Article Details

### Beginner (Articles 1-8)

Each uses one AWS CLI command and maps directly to one observation field.

**1. CTL.S3.PUBLIC.001 — No Public S3 Bucket Read**

File: `1.md` 

Bucket policy grants `s3:GetObject` to `Principal: "*"`. Anyone can read objects.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.public_read`
Fix: Remove `Principal: "*"` Allow statement for `s3:GetObject`.

---

**2. CTL.S3.CONTROLS.001 — Public Access Block Must Be Enabled**

Block Public Access is not fully enabled. The bucket has no safety net against accidental public exposure.

CLI: `aws s3api get-public-access-block --bucket <name>`
Field: `properties.storage.controls.public_access_fully_blocked`
Fix: Enable all four Block Public Access settings.

---

**3. CTL.S3.ENCRYPT.001 — Encryption at Rest Required**

Bucket has no default encryption. Objects stored in plaintext on disk.

CLI: `aws s3api get-bucket-encryption --bucket <name>`
Field: `properties.storage.encryption.at_rest_enabled`
Fix: Enable SSE-S3 or SSE-KMS default encryption.

---

**4. CTL.S3.LOG.001 — Access Logging Required**

No server access logging. No audit trail for who accessed what data.

CLI: `aws s3api get-bucket-logging --bucket <name>`
Field: `properties.storage.logging.enabled`
Fix: Enable server access logging to a dedicated log bucket.

---

**5. CTL.S3.VERSION.001 — Versioning Required**

Versioning disabled. Deleted or overwritten objects cannot be recovered.

CLI: `aws s3api get-bucket-versioning --bucket <name>`
Field: `properties.storage.versioning.enabled`
Fix: Enable versioning.

---

**6. CTL.S3.VERSION.002 — Backup Buckets Must Have MFA Delete Enabled**

Backup-tagged bucket has versioning but no MFA Delete. An attacker with stolen credentials can permanently delete versions.

CLI: `aws s3api get-bucket-versioning --bucket <name>`
Field: `properties.storage.versioning.mfa_delete`
Fix: Enable MFA Delete on the bucket.

---

**7. CTL.S3.GOVERNANCE.001 — Data Classification Tag Required**

Bucket missing `data-classification` tag. All sensitivity-gated controls (PHI, PII, confidential) silently pass because they cannot evaluate.

CLI: `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.tags.data-classification`
Fix: Add tag with value like `confidential`, `phi`, `internal`, or `public`.

---

**8. CTL.S3.INCOMPLETE.001 — Complete Data Required for Safety Assessment**

Observation snapshot is missing required fields. Stave cannot make a safety determination with incomplete data.

CLI: multiple (whichever fields are missing)
Field: Various — depends on what is incomplete
Fix: Ensure the extractor populates all required fields.

---

### Intermediate (Articles 9-29)

Policy and ACL parsing with `jq` conditionals. Some articles require two CLI commands.

**9. CTL.S3.ENCRYPT.002 — Transport Encryption Required**

No HTTPS enforcement. Data can transit in plaintext.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.encryption.in_transit_enforced`
jq: Parse policy for Deny + `Condition.Bool.aws:SecureTransport = "false"`.
Fix: Add Deny statement requiring `aws:SecureTransport`.

---

**10. CTL.S3.PUBLIC.007 — No Public Read via Policy**

Policy statement explicitly grants `s3:GetObject` to `Principal: "*"`.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.read_via_resource`
Fix: Remove the public read statement.

---

**11. CTL.S3.PUBLIC.008 — No Public List via Policy**

Policy grants `s3:ListBucket` to `Principal: "*"`. Object names and structure exposed.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.list_via_identity`
Fix: Remove the public list statement.

---

**12. CTL.S3.PUBLIC.003 — No Public Write Access**

Policy grants `s3:PutObject` or `s3:DeleteObject` to `Principal: "*"`. Enables data injection and ransomware.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.public_write`
Fix: Remove public write statements.

---

**13. CTL.S3.ACCESS.002 — No Wildcard Action Policies**

Policy uses `Action: "s3:*"`. Grants all permissions — read, write, delete, reconfigure.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.has_wildcard_policy`
jq: Check if any statement has `Action == "s3:*"` or `Action == "*"`.
Fix: Replace with specific actions.

---

**14. CTL.S3.ACCESS.003 — No External Write Access**

External AWS account has write access to the bucket.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.has_external_write`
Fix: Remove external write grants or restrict to read-only.

---

**15. CTL.S3.NETWORK.001 — Public-Principal Policies Must Have Network Conditions**

`Principal: "*"` Allow statement has no VPC or IP condition. Access is internet-wide.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Fields: `properties.storage.access.has_vpc_condition`, `has_ip_condition`, `effective_network_scope`
jq: Check for `Condition` with `aws:SourceVpc` or `aws:SourceIp`.
Fix: Add VPC endpoint or source IP conditions.

---

**16. CTL.S3.PUBLIC.004 — No Public Read via ACL**

ACL grants READ to AllUsers. Objects readable without authentication.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.access.public_read` (via ACL path)
jq: Check `Grants` for grantee URI containing `AllUsers` with `READ` permission.
Fix: Remove AllUsers READ grant.

---

**17. CTL.S3.ACL.WRITE.001 — No Public Write via ACL**

ACL grants WRITE to AllUsers. Anyone can upload or delete objects.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.access.write_via_resource`
Fix: Remove AllUsers WRITE grant.

---

**18. CTL.S3.ACL.FULLCONTROL.001 — No FULL_CONTROL ACL Grants to Public**

ACL grants FULL_CONTROL to AllUsers. Anyone can read, write, and change permissions.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.acl.public_full_control`
Fix: Remove AllUsers FULL_CONTROL grant.

---

**19. CTL.S3.ACL.RECON.001 — No Public ACL Readability**

ACL grants READ_ACP to AllUsers. Anyone can read the bucket's ACL and discover who has access.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.acl.public_read_acp`
Fix: Remove AllUsers READ_ACP grant.

---

**20. CTL.S3.ACL.ESCALATION.001 — No Public ACL Modification**

ACL grants WRITE_ACP to AllUsers. Anyone can modify the bucket's ACL and grant themselves full access.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.acl.public_write_acp`
Fix: Remove AllUsers WRITE_ACP grant.

---

**21. CTL.S3.AUTH.READ.001 — No Authenticated-Users Read Access**

ACL grants READ to AuthenticatedUsers. Any AWS account holder worldwide can read objects. Often confused with "internal only."

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.access.authenticated_read`
Fix: Replace AuthenticatedUsers grants with specific account ARNs.

---

**22. CTL.S3.AUTH.WRITE.001 — No Authenticated-Users Write Access**

ACL grants WRITE to AuthenticatedUsers. Any AWS account holder can upload or delete objects.

CLI: `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.access.authenticated_write`
Fix: Replace AuthenticatedUsers grants with specific account ARNs.

---

**23. CTL.S3.PUBLIC.LIST.001 — No Public S3 Bucket Listing**

Bucket allows public listing via policy or ACL. Object names, sizes, and dates exposed.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-bucket-acl --bucket <name>`
Field: `properties.storage.access.public_list`
Fix: Remove public list grants from policy and ACL.

---

**24. CTL.S3.PUBLIC.LIST.002 — Anonymous S3 Listing Must Be Explicitly Intended**

Public listing is enabled but no explicit opt-in tag. Listing may be accidental.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-bucket-acl --bucket <name>`
Fields: `properties.storage.access.public_list`, `properties.storage.tags`
Fix: Remove public listing or add an explicit intent tag.

---

**25. CTL.S3.PUBLIC.005 — No Latent Public Read Exposure**

Block Public Access masks a public policy. If Block Public Access is removed, bucket becomes instantly public. Safe now but fragile.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-public-access-block --bucket <name>`
Field: `properties.storage.access.latent_public_read`
Fix: Remove the underlying public policy so Block Public Access is defense-in-depth, not the only barrier.

---

**26. CTL.S3.PUBLIC.006 — No Latent Public Bucket Listing**

Block Public Access masks a public listing grant. Same fragility as latent read.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-public-access-block --bucket <name>`
Field: `properties.storage.access.latent_public_list`
Fix: Remove the underlying public listing grant.

---

**27. CTL.S3.ACCESS.001 — No Unauthorized Cross-Account Access**

Policy grants access to an AWS account not in the allowlist.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.access.external_account_ids`
Params: `allowed_accounts` — the reader customizes which accounts are permitted.
Fix: Remove unauthorized account or add to `params.allowed_accounts`.

---

**28. CTL.S3.PUBLIC.002 — No Public S3 Buckets With Sensitive Data**

Bucket is tagged `data-classification: confidential` but allows public read. Data classification contradicts access.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Fields: `properties.storage.access.public_read`, `properties.storage.tags.data-classification`
Fix: Remove public read or reclassify the data.

---

**29. CTL.S3.PUBLIC.PREFIX.001 — Protected Prefixes Must Not Be Publicly Readable**

Specific prefixes (`invoices/`, `secrets/`) are publicly readable even if other prefixes are intentionally public.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-bucket-acl --bucket <name>`
Params: `protected_prefixes`, `allowed_public_prefixes`
Fix: Remove public grants for protected prefixes.

---

### Advanced (Articles 30-43)

Tag-conditional evaluation, compliance controls, cross-service analysis.

**30. CTL.S3.ENCRYPT.003 — PHI Buckets Must Use SSE-KMS with Customer-Managed Key**

PHI-tagged bucket uses SSE-S3 instead of SSE-KMS with customer-managed key. Compliance requires key control.

CLI: `aws s3api get-bucket-encryption --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Fields: `properties.storage.encryption.algorithm`, `properties.storage.encryption.kms_key_id`, `properties.storage.tags.data-classification`
Fix: Switch to SSE-KMS with a customer-managed KMS key.

---

**31. CTL.S3.ENCRYPT.004 — Sensitive Data Requires KMS Encryption**

Bucket tagged with any sensitive classification lacks KMS encryption.

CLI: `aws s3api get-bucket-encryption --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Fields: Same as article 30.
Fix: Enable SSE-KMS encryption.

---

**32. CTL.S3.LIFECYCLE.001 — Retention-Tagged Buckets Must Have Lifecycle Rules**

Bucket tagged for retention has no lifecycle rules. Data accumulates without expiration or transition.

CLI: `aws s3api get-bucket-lifecycle-configuration --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.lifecycle.rules_configured`
Fix: Add lifecycle rules matching retention requirements.

---

**33. CTL.S3.LIFECYCLE.002 — PHI Buckets Must Not Expire Data Before Minimum Retention**

PHI-tagged bucket has lifecycle rules that expire data before the regulatory minimum.

CLI: `aws s3api get-bucket-lifecycle-configuration --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.lifecycle.min_expiration_days`
Fix: Extend lifecycle expiration to meet retention requirements.

---

**34. CTL.S3.LOCK.001 — Compliance-Tagged Buckets Must Have Object Lock Enabled**

Compliance-tagged bucket has no Object Lock. Data can be deleted by anyone with permissions.

CLI: `aws s3api get-object-lock-configuration --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.lock.enabled`
Fix: Enable Object Lock (requires creating a new bucket with lock enabled).

---

**35. CTL.S3.LOCK.002 — PHI Buckets Must Use COMPLIANCE Mode Object Lock**

PHI-tagged bucket uses GOVERNANCE mode Object Lock. Admin can override retention.

CLI: `aws s3api get-object-lock-configuration --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.lock.mode`
Fix: Switch to COMPLIANCE mode.

---

**36. CTL.S3.LOCK.003 — PHI Object Lock Retention Must Meet Minimum Period**

PHI-tagged bucket's Object Lock retention period is shorter than required.

CLI: `aws s3api get-object-lock-configuration --bucket <name>` + `aws s3api get-bucket-tagging --bucket <name>`
Field: `properties.storage.lock.retention_days`
Fix: Extend retention period to regulatory minimum.

---

**37. CTL.S3.WEBSITE.PUBLIC.001 — No Public Website Hosting with Public Read**

Bucket has static website hosting enabled AND public read. Creates a public web server.

CLI: `aws s3api get-bucket-website --bucket <name>` + `aws s3api get-bucket-policy --bucket <name>`
Fields: `properties.storage.website.enabled`, `properties.storage.access.public_read`
Fix: Disable website hosting or use CloudFront with OAI.

---

**38. CTL.S3.REPO.ARTIFACT.001 — Public Buckets Must Not Expose VCS Artifacts**

Public bucket contains `.git/`, `.env`, or other VCS/config artifacts. Source code and secrets exposed.

CLI: `aws s3api list-objects-v2 --bucket <name> --prefix .git/ --max-keys 1` + `aws s3api get-bucket-policy --bucket <name>`
Fields: `properties.storage.artifacts.has_vcs_artifacts`, `properties.storage.access.public_read`
Fix: Delete VCS artifacts or remove public access.

---

**39. CTL.S3.WRITE.SCOPE.001 — S3 Signed Upload Must Bind To Exact Object Key**

Pre-signed upload policy allows uploads to arbitrary keys. Users can overwrite any object.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.upload.key_bound`
Fix: Add `s3:prefix` or `starts-with` conditions to upload policies.

---

**40. CTL.S3.WRITE.CONTENT.001 — S3 Signed Upload Must Restrict Content Types**

Pre-signed upload policy does not restrict content types. Users can upload executables or malware.

CLI: `aws s3api get-bucket-policy --bucket <name>` + `aws s3api get-bucket-cors --bucket <name>`
Field: `properties.storage.upload.content_type_restricted`
Fix: Add `Content-Type` conditions to upload policies.

---

**41. CTL.S3.TENANT.ISOLATION.001 — Shared-Bucket Tenant Isolation Must Enforce Prefix**

Multi-tenant bucket policy does not enforce prefix-based isolation. One tenant can access another's data.

CLI: `aws s3api get-bucket-policy --bucket <name>`
Field: `properties.storage.tenant.prefix_enforced`
Fix: Add per-tenant prefix conditions using `s3:prefix` and `${aws:PrincipalTag/tenant-id}`.

---

**42. CTL.S3.BUCKET.TAKEOVER.001 — Referenced S3 Buckets Must Exist And Be Owned**

A DNS record or CloudFront distribution references an S3 bucket that does not exist. An attacker can create it and serve content.

CLI: `aws s3api list-buckets` + `aws cloudfront list-distributions`
Field: `properties.storage.ownership.exists`
Fix: Create the referenced bucket or remove the dangling reference.

---

**43. CTL.S3.DANGLING.ORIGIN.001 — CDN S3 Origins Must Not Be Dangling**

CloudFront distribution has an S3 origin that is not owned. Content can be hijacked.

CLI: `aws s3api list-buckets` + `aws cloudfront list-distributions`
Field: `properties.storage.ownership.origin_valid`
Fix: Create the origin bucket or update the distribution.

---

### Capstone (Article 44)

**44. Full Hardening Audit**

Audit one bucket against all 43 controls. Combines all AWS CLI commands into one complete observation. Build a reusable extractor script.

CLI:
```bash
BUCKET=production-data
aws s3api get-bucket-policy --bucket $BUCKET
aws s3api get-public-access-block --bucket $BUCKET
aws s3api get-bucket-encryption --bucket $BUCKET
aws s3api get-bucket-logging --bucket $BUCKET
aws s3api get-bucket-versioning --bucket $BUCKET
aws s3api get-bucket-acl --bucket $BUCKET
aws s3api get-bucket-tagging --bucket $BUCKET
aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET
aws s3api get-object-lock-configuration --bucket $BUCKET
aws s3api get-bucket-website --bucket $BUCKET
aws s3api get-bucket-cors --bucket $BUCKET
aws s3api list-objects-v2 --bucket $BUCKET --prefix .git/ --max-keys 1
```

One `jq` script. One observation file. All 43 controls evaluated. All violations shown. All fixes verified.

---

## Writing Guidelines

Each article must include:

1. **Title**: the control name
2. **One sentence**: what goes wrong
3. **AWS CLI command and raw output**: exact command, full JSON response (bad state)
4. **jq extraction**: complete command producing valid `obs.v0.1` (bad observation)
5. **`stave apply` command and output**: showing the violation (exit code 3)
6. **Fixed AWS CLI output**: full JSON response (good state)
7. **jq extraction**: complete command producing valid `obs.v0.1` (good observation)
8. **`stave verify --before ... --after ...`**: showing the finding is resolved
9. **Control reference**: control ID, severity, observation field checked

---

Missing item numbers:

**1, 3, 11, 17**

They are:

* **1** — No Public S3 Bucket Read
* **3** — Encryption at Rest Required
* **11** — No Public List via Policy
* **17** — No Public Write via ACL

# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`

**Total controls:** 43
**Pack hash:** `853b2485a07396a55f0ef421159807db391eab7282c1d4d3e83059506c0dcb67`

## Summary

| Severity | Count |
|----------|-------|
| critical | 10 |
| high | 20 |
| low | 2 |
| medium | 11 |

| Domain | Count |
|--------|-------|
| exposure | 40 |
| storage | 3 |

## Controls

### CTL.S3.ACCESS.001

**No Unauthorized Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 1.16; pci_dss_v3.2.1: 7.1; soc2: CC6.3;

S3 bucket policies must not grant access to external AWS accounts. `allowed_accounts` contains trusted external AWS account IDs (12-digit). Access from accounts outside this allowlist is unsafe.

**Remediation:** Review bucket policy Principal elements for external account IDs. Remove statements granting access to accounts not in your organization. Use aws:PrincipalOrgID condition to restrict access to your AWS Organization.

---

### CTL.S3.ACCESS.002

**No Wildcard Action Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not use wildcard actions (s3:* or *). Wildcard policies grant more permissions than intended and violate the principle of least privilege.

**Remediation:** Replace wildcard actions with specific S3 actions required by the use case (e.g., s3:GetObject, s3:PutObject). Audit which principals use this policy and scope actions to their actual needs.

---

### CTL.S3.ACCESS.003

**No External Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete permissions to external AWS accounts. Cross-account read access may be acceptable for analytics or auditing, but write access from external accounts creates data integrity and supply chain risks.

**Remediation:** Remove bucket policy statements granting s3:PutObject, s3:DeleteObject, or s3:PutBucketPolicy to external accounts. If cross-account write is required, restrict to specific account IDs with condition keys.

---

### CTL.S3.ACL.ESCALATION.001

**No Public ACL Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not be writable by AllUsers or AuthenticatedUsers. WRITE_ACP permission enables attackers to modify the ACL itself, granting themselves FULL_CONTROL and escalating to read, write, and delete all objects.

**Remediation:** Remove WRITE_ACP grants from the bucket ACL and remove policy statements granting s3:PutBucketAcl or s3:PutObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.FULLCONTROL.001

**No FULL_CONTROL ACL Grants to Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not grant FULL_CONTROL to AllUsers or AuthenticatedUsers. FULL_CONTROL is the worst-case ACL misconfiguration — the grantee can read, write, and delete objects and modify the ACL itself.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the FULL_CONTROL grant to public groups. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.ACL.RECON.001

**No Public ACL Readability**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs should not be readable by unauthenticated users. READ_ACP permission enables attackers to enumerate ACL grants, discover which principals have access, and find escalation paths.

**Remediation:** Remove READ_ACP grants from the bucket ACL and remove policy statements granting s3:GetBucketAcl or s3:GetObjectAcl to public principals. Enable S3 Public Access Block with BlockPublicAcls set to true.

---

### CTL.S3.ACL.WRITE.001

**No Public Write via ACL**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket ACLs must not grant write access to AllUsers or AuthenticatedUsers. ACL-based write access enables attackers to upload malicious objects or overwrite existing content.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the public write grant. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.AUTH.READ.001

**No Authenticated-Users Read Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant read access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account can read objects, which is nearly as dangerous as fully public access.

**Remediation:** Remove the ACL grant to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with IgnorePublicAcls set to true.

---

### CTL.S3.AUTH.WRITE.001

**No Authenticated-Users Write Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not grant write or delete access to all authenticated AWS users. AuthenticatedUsers scope means any AWS account holder worldwide can upload, overwrite, or delete objects — enabling data injection, ransomware, and supply chain poisoning.

**Remediation:** Remove the ACL grant or policy statement granting write access to AuthenticatedUsers. Replace with specific IAM principals or use bucket policy with explicit account IDs. Enable S3 Public Access Block with BlockPublicAcls and IgnorePublicAcls set to true.

---

### CTL.S3.BUCKET.TAKEOVER.001

**Referenced S3 Buckets Must Exist And Be Owned**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

Any externally referenced S3 bucket must exist and be owned. Dangling references (missing or unowned buckets) enable bucket takeover and attacker-controlled content delivery.

**Remediation:** Create the S3 bucket in your AWS account, or remove the DNS record, CDN origin, or application reference pointing to the unclaimed bucket.

---

### CTL.S3.CONTROLS.001

**Public Access Block Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; pci_dss_v3.2.1: 1.3.6; soc2: CC6.1;

S3 buckets must have the public access block fully enabled. When disabled, the bucket has no safety net against accidental public exposure from policy or ACL changes. This detects the enabling condition for public access, not the exposure itself.

**Remediation:** Enable all four Public Access Block settings on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.

---

### CTL.S3.DANGLING.ORIGIN.001

**CDN S3 Origins Must Not Be Dangling**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

CloudFront distributions must not reference S3 origins that do not exist. A missing/unclaimed origin bucket enables takeover and CDN content poisoning.

**Remediation:** Create the S3 bucket in your AWS account to claim the name, or remove the dangling origin from the CloudFront distribution. Update the distribution to use an Origin Access Control (OAC).

---

### CTL.S3.ENCRYPT.001

**Encryption at Rest Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.1; pci_dss_v3.2.1: 3.4; soc2: CC6.1;

S3 buckets must have server-side encryption enabled. Unencrypted storage is the top audit finding in regulated industries.

**Remediation:** Enable default bucket encryption using SSE-S3 (AES256) or SSE-KMS. Use aws s3api put-bucket-encryption to set the default encryption configuration. For sensitive data, use SSE-KMS with a customer-managed key.

---

### CTL.S3.ENCRYPT.002

**Transport Encryption Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.2; pci_dss_v3.2.1: 4.1; soc2: CC6.1;

S3 buckets must enforce HTTPS via a deny policy on aws:SecureTransport=false. Without this, data transfers occur in plaintext.

**Remediation:** Add a bucket policy statement that denies all actions when aws:SecureTransport is false. This forces all API calls to use HTTPS.

---

### CTL.S3.ENCRYPT.003

**PHI Buckets Must Use SSE-KMS with Customer-Managed Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi must use SSE-KMS encryption with a customer-managed key (CMK), not the default AWS-managed key or SSE-S3. This ensures the organization controls key rotation, access policies, and audit logging for PHI data at rest.

**Remediation:** Change the bucket default encryption to SSE-KMS and specify a customer-managed KMS key ARN. Ensure the KMS key policy grants access only to authorized principals. Enable KMS key rotation.

---

### CTL.S3.ENCRYPT.004

**Sensitive Data Requires KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets with any non-public data classification must use SSE-KMS encryption with a customer-managed key, not SSE-S3 (AES256). AES256 uses AWS-managed keys with no customer control over key rotation, access policies, or audit trails. This fires on all classified data except explicitly public or non-sensitive buckets.

**Remediation:** Change the bucket default encryption to SSE-KMS with a customer-managed key. Re-encrypt existing objects by copying them in place with the new encryption settings.

---

### CTL.S3.GOVERNANCE.001

**Data Classification Tag Required**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must have a data-classification tag. Without this tag, tag-conditional controls for PHI, PII, confidential data, backup integrity, and compliance retention cannot evaluate — the bucket silently passes all sensitivity-gated checks regardless of actual content.

**Remediation:** Add a data-classification tag to the bucket with an appropriate value (e.g., phi, pii, confidential, internal, public, non-sensitive). Update your tagging policy to require this tag on all S3 buckets.

---

### CTL.S3.INCOMPLETE.001

**Complete Data Required for Safety Assessment**

- **Severity:** low
- **Type:** unsafe_duration
- **Domain:** storage

S3 bucket safety cannot be proven when policy or ACL data is missing from the snapshot.

**Remediation:** Re-run the observation collector with full permissions to read bucket policies and ACLs. Ensure the collector IAM role has s3:GetBucketPolicy, s3:GetBucketAcl, and s3:GetBucketPolicyStatus permissions.

---

### CTL.S3.LIFECYCLE.001

**Retention-Tagged Buckets Must Have Lifecycle Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-retention must have at least one enabled lifecycle rule configured. HIPAA requires defined data retention policies for protected health information (PHI), audit logs, and billing records. Without lifecycle rules, data persists indefinitely, increasing exposure surface and violating retention policy requirements.

**Remediation:** Add S3 lifecycle rules to manage object expiration and transitions. Configure rules matching the retention period specified in the data-retention tag. Use lifecycle transitions to move data to cheaper storage classes before expiration.

---

### CTL.S3.LIFECYCLE.002

**PHI Buckets Must Not Expire Data Before Minimum Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi must not have lifecycle expiration rules that delete data before the minimum HIPAA retention period. HIPAA requires medical records to be retained for a minimum of 6 years (2190 days). This control detects PHI buckets with expiration rules set below this threshold, which could result in premature deletion of protected health information.

**Remediation:** Increase the lifecycle expiration period to at least the configured min_retention_days value. If the current rule is for storage class transition, ensure the expiration rule is separate and meets the minimum retention period.

---

### CTL.S3.LOCK.001

**Compliance-Tagged Buckets Must Have Object Lock Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** soc2: CC6.1;

S3 buckets tagged with any compliance framework (soc2, gdpr, hipaa, pci-dss, etc.) must have S3 Object Lock enabled. Object Lock provides WORM (Write Once Read Many) protection, preventing objects from being deleted or overwritten for a specified retention period. Regulatory frameworks require immutable storage for audit logs, compliance records, and protected data.

**Remediation:** Enable S3 Object Lock on the bucket. Note: Object Lock can only be enabled at bucket creation. If the bucket already exists, create a new bucket with Object Lock enabled and migrate objects. Set a default retention period appropriate for your compliance framework.

---

### CTL.S3.LOCK.002

**PHI Buckets Must Use COMPLIANCE Mode Object Lock**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must use COMPLIANCE mode, not GOVERNANCE mode. COMPLIANCE mode prevents ANY user, including the root account, from deleting or overwriting protected objects during the retention period. GOVERNANCE mode allows users with special permissions to override retention, which is insufficient for HIPAA-regulated PHI data where tamper-proof storage is required.

**Remediation:** Change the Object Lock default retention mode from GOVERNANCE to COMPLIANCE. In COMPLIANCE mode, no user (including root) can delete or modify protected objects during the retention period.

---

### CTL.S3.LOCK.003

**PHI Object Lock Retention Must Meet Minimum Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with data-classification=phi that have Object Lock enabled must have a default retention period of at least 2190 days (6 years) to meet HIPAA minimum retention requirements. Shorter retention periods risk premature expiration of WORM protection, allowing deletion or modification of PHI data before the regulatory retention period has elapsed.

**Remediation:** Increase the Object Lock default retention period to at least 2190 days. Use aws s3api put-object-lock-configuration to update the default retention settings.

---

### CTL.S3.LOG.001

**Access Logging Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; pci_dss_v3.2.1: 10.2.1; soc2: CC7.2;

S3 buckets must have server access logging enabled for audit trail and visibility into data access patterns.

**Remediation:** Enable S3 server access logging and specify a target bucket for log delivery. Ensure the target bucket has appropriate access controls and is in the same region.

---

### CTL.S3.NETWORK.001

**Public-Principal Policies Must Have Network Conditions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies that grant access to Principal * (any AWS principal) must include network-scoping conditions such as aws:SourceIp, aws:sourceVpce, aws:SourceVpc, or aws:PrincipalOrgID. Without these conditions, the bucket is accessible to anyone on the internet. This control detects policies where wildcard principals are used without network restrictions.

**Remediation:** Add network-scoping conditions to the bucket policy: aws:SourceIp for IP range restrictions, aws:SourceVpce for VPC endpoint restrictions, aws:SourceVpc for VPC restrictions, or aws:PrincipalOrgID for organization-only access.

---

### CTL.S3.PUBLIC.001

**No Public S3 Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.5; pci_dss_v3.2.1: 1.2.1; soc2: CC6.1;

S3 buckets must not allow public read access. Detects buckets with anonymous read exposure via policy or ACL.

**Remediation:** Enable S3 Public Access Block (all four settings). Remove any bucket policy statements granting access to Principal "*". Remove any ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.PUBLIC.002

**No Public S3 Buckets With Sensitive Data**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with sensitive data classifications (PHI, PII, confidential) must not allow any public access.

**Remediation:** Immediately enable S3 Public Access Block (all four settings). Remove bucket policy statements granting access to Principal "*". Remove ACL grants to AllUsers or AuthenticatedUsers. Audit CloudTrail logs for unauthorized access during the exposure window.

---

### CTL.S3.PUBLIC.003

**No Public Write Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow public write or delete access. Public write enables data injection, ransomware, and policy takeover.

**Remediation:** Remove bucket policy statements that grant s3:PutObject or s3:DeleteObject to Principal "*". Remove ACL grants that allow WRITE or FULL_CONTROL to AllUsers or AuthenticatedUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.004

**No Public Read via ACL**

- **Severity:** medium
- **Type:** unsafe_duration
- **Domain:** storage

S3 bucket ACLs must not grant read access to AllUsers or AuthenticatedUsers for PHI data.

**Remediation:** Replace the bucket ACL with "BucketOwnerFullControl" or remove the public read grant. Enable S3 Public Access Block with IgnorePublicAcls set to true to override ACL-based public access.

---

### CTL.S3.PUBLIC.005

**No Latent Public Read Exposure**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** storage

S3 buckets must not have latent public read exposure where a public mechanism (policy or ACL) is masked only by Public Access Block. Removing PAB would immediately expose the bucket.

**Remediation:** Remove the underlying public-granting policy statement or ACL entry so the bucket does not depend solely on PAB for protection. Then verify PAB remains enabled as defense-in-depth.

---

### CTL.S3.PUBLIC.006

**No Latent Public Bucket Listing**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket has a policy or ACL that would allow public listing if the public access block were removed. The public access block is currently the only control preventing directory enumeration. This is a latent vulnerability — one configuration change away from exposing all object keys.

**Remediation:** Remove the underlying policy statement or ACL entry that grants s3:ListBucket to Principal "*" or AllUsers. Do not rely solely on PAB to prevent directory enumeration.

---

### CTL.S3.PUBLIC.007

**No Public Read via Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant public read access.

**Remediation:** Remove or constrain the public policy statement. Use restrictive principals or conditions and keep Public Access Block enabled.

---

### CTL.S3.PUBLIC.008

**No Public List via Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 bucket policies must not grant anonymous object listing.

**Remediation:** Remove or constrain policy statements allowing s3:ListBucket to anonymous principals.

---

### CTL.S3.PUBLIC.LIST.001

**No Public S3 Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets must not allow anonymous listing of objects. Public listing exposes object keys, enabling targeted data exfiltration.

**Remediation:** Remove bucket policy statements that grant s3:ListBucket to Principal "*". Remove ACL grants that allow READ to AllUsers. Enable S3 Public Access Block.

---

### CTL.S3.PUBLIC.LIST.002

**Anonymous S3 Listing Must Be Explicitly Intended**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Anonymous bucket listing increases exposure surface even when objects are public by design. Listing must be explicitly intended via tag.

**Remediation:** If listing is intentional, add the tag public_list_intended=true to the bucket. Otherwise, remove the policy or ACL granting s3:ListBucket to Principal "*" or AllUsers.

---

### CTL.S3.PUBLIC.PREFIX.001

**Protected Prefixes Must Not Be Publicly Readable**

- **Severity:** high
- **Type:** prefix_exposure
- **Domain:** exposure

S3 bucket prefixes marked as protected must not be publicly readable. Evaluates bucket policies, ACL grants, and public access block settings to determine effective public read access for each protected prefix. Customize the prefix lists below to match your bucket layout.

**Remediation:** 1. Review the protected_prefixes and allowed_public_prefixes lists
   in this control and adjust them to match your bucket layout.
2. Enable S3 Public Access Block to restrict policy and ACL exposure. 3. Remove bucket policy statements granting s3:GetObject to Principal "*"
   for protected prefixes.
4. Remove ACL grants to AllUsers or AuthenticatedUsers.

---

### CTL.S3.REPO.ARTIFACT.001

**Public Buckets Must Not Expose VCS Artifacts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

Buckets that serve public content must not expose version control artifacts such as .git/ or .svn/. Presence of these paths enables repo reconstruction and can leak secrets.

**Remediation:** Remove .git/, .svn/, and other VCS directories from the bucket. Add a lifecycle rule or deployment script that excludes VCS artifacts from uploads. If the bucket is a static website, configure your build pipeline to strip VCS files before deployment.

---

### CTL.S3.TENANT.ISOLATION.001

**Shared-Bucket Tenant Isolation Must Enforce Prefix**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

When a shared S3 bucket uses prefix-based tenant isolation, every app-signer identity that produces presigned URLs must enforce the tenant prefix.  An identity that allows path traversal (../) or disables prefix enforcement lets one tenant read or overwrite another tenant's objects.

**Remediation:** Update the app-signer configuration to enforce tenant prefix restrictions (enforce_prefix=true) and block path traversal (allow_traversal=false) on all presigned URL signers.

---

### CTL.S3.VERSION.001

**Versioning Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.1.3; soc2: CC6.1;

S3 buckets must have versioning enabled to protect against accidental deletion and enable recovery from negligent operations.

**Remediation:** Enable versioning on the bucket using aws s3api put-bucket-versioning. Once enabled, configure lifecycle rules to manage noncurrent versions and control storage costs.

---

### CTL.S3.VERSION.002

**Backup Buckets Must Have MFA Delete Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets tagged with backup=true must have MFA delete enabled. MFA delete requires multi-factor authentication to permanently delete object versions, protecting against ransomware attacks and accidental mass deletion of backup data. Without MFA delete, any principal with s3:DeleteObject permission can permanently destroy backup versions.

**Remediation:** Enable MFA delete on the bucket using aws s3api put-bucket-versioning with the MFA flag. This requires the root account credentials and an MFA device. Only the root account can enable or disable MFA delete.

---

### CTL.S3.WEBSITE.PUBLIC.001

**No Public Website Hosting with Public Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

S3 buckets with static website hosting enabled must not also have public read access. Website hosting combined with public read serves content directly to the internet.

**Remediation:** If public hosting is not intended, disable static website hosting and remove public read access. If hosting is intended, move content behind CloudFront with an Origin Access Control (OAC) and remove direct public access from the bucket.

---

### CTL.S3.WRITE.CONTENT.001

**S3 Signed Upload Must Restrict Content Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict allowed content types. Unrestricted content types enable attackers to upload SVGs with embedded JavaScript or HTML files, causing stored XSS when served from the bucket's domain.

**Remediation:** Add an exact content-type condition to the signed upload policy (e.g., eq $Content-Type image/jpeg). Avoid starts-with with empty prefix, which allows any content type.

---

### CTL.S3.WRITE.SCOPE.001

**S3 Signed Upload Must Bind To Exact Object Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure

Signed upload policies must restrict write permission to a single exact object key. Prefix-wide permissions (e.g., starts-with $key files/) enable arbitrary overwrite and cross-tenant tampering.

**Remediation:** Change the signed upload policy to use an exact key condition (eq instead of starts-with) that binds each upload to a specific object path. Generate unique object keys server-side.

---


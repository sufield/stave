# Control Reference — S3EXPRESS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.S3EXPRESS.ACCESS.EXTERNAL.001

**No Unauthorized External Access to Directory Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Directory Bucket policies must not grant access to external AWS accounts without organization-scoping conditions. The s3express: IAM namespace is separate from s3:, so s3:-scoped RCPs that enforce data perimeters do not cover Directory Buckets.

**Remediation:** Remove external account access or add aws:PrincipalOrgID condition. Verify s3express:-scoped SCP/RCP coverage exists independently of s3: policies.

---

### CTL.S3EXPRESS.ENCRYPT.001

**Directory Bucket Encryption at Rest Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

S3 Express Directory Buckets must have server-side encryption enabled. Directory Buckets support SSE-S3 (default) and SSE-KMS. This control verifies encryption is not disabled or downgraded.

**Remediation:** Enable default encryption using SSE-S3 or SSE-KMS on the Directory Bucket.

---

### CTL.S3EXPRESS.POLICY.CROSSACCOUNT.001

**Directory Bucket Policy Must Restrict Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Directory Bucket policies granting cross-account access must include an aws:PrincipalOrgID condition. The s3express: namespace is separate from s3:, so RCPs scoped to s3:* that enforce PrincipalOrgID do not cover Directory Buckets.

**Remediation:** Add aws:PrincipalOrgID condition to all Allow statements that grant access to external accounts. Verify SCP coverage for s3express: actions separately from s3: actions.

---

### CTL.S3EXPRESS.POLICY.PUBLIC.001

**Directory Bucket Policy Must Not Permit Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

S3 Express Directory Bucket policies must not grant access to anonymous or wildcard principals. Directory Buckets use the s3express: IAM namespace, which is separate from s3:. Organization-level S3 Block Public Access and RCPs scoped to s3:* do not cover s3express: actions. A public policy on a Directory Bucket is invisible to s3:-scoped defenses.

**Remediation:** Remove wildcard Principal statements from the Directory Bucket policy. Add aws:PrincipalOrgID condition to restrict access to your AWS Organization. Verify that any SCP or RCP covering s3express: actions is in place — s3:* SCPs do not apply.

---

### CTL.S3EXPRESS.RESILIENCE.NOVERSIONING.001

**Directory Bucket Has No Versioning or Object Lock**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

S3 Express Directory Buckets do not support versioning, Object Lock, or cross-region replication. Data in a Directory Bucket has no S3-native ransomware resilience. This control fires on production Directory Buckets to ensure compensating controls (AWS Backup, cross-account copy, application-layer snapshots) are documented. This is a design limitation of S3 Express One Zone, not a misconfiguration.

**Remediation:** Implement compensating controls: AWS Backup with cross-account vault, periodic cross-account copy to a versioned S3 bucket, or application-layer snapshot mechanisms. Document the compensating control in the bucket's tags.

---

### CTL.S3EXPRESS.SESSION.SCOPE.001

**CreateSession Must Be Resource-Scoped**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

s3express:CreateSession returns temporary data-plane credentials for a specific Directory Bucket. An IAM policy granting CreateSession with Resource: * allows the principal to obtain credentials for ANY Directory Bucket in the account. This is equivalent to granting s3:GetObject + s3:PutObject on all Directory Buckets — a broad data-access grant hidden behind a single action.

**Remediation:** Scope the s3express:CreateSession Allow statement to specific Directory Bucket ARNs. Use Resource conditions to limit which buckets the role can create sessions for.

---


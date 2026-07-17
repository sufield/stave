# Control Reference — S3VECTORS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.S3VECTORS.ACCESS.EXTERNAL.001

**No Unauthorized External Access to Vector Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Vector Bucket policies must not grant access to external AWS accounts without organization-scoping conditions. The s3vectors: IAM namespace is separate from s3:, so s3:-scoped RCPs that enforce data perimeters do not cover Vector Buckets.

**Remediation:** Remove external account access or add aws:PrincipalOrgID condition. Verify s3vectors:-scoped SCP/RCP coverage exists.

---

### CTL.S3VECTORS.POLICY.CROSSACCOUNT.001

**Vector Bucket Policy Must Restrict Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Vector Bucket policies granting cross-account access must include an aws:PrincipalOrgID condition. The s3vectors: namespace is separate from s3:, so RCPs scoped to s3:* that enforce PrincipalOrgID do not cover Vector Buckets. An unscoped cross-account grant exposes embedding data to external principals.

**Remediation:** Add aws:PrincipalOrgID condition to all Allow statements that grant access to external accounts.

---

### CTL.S3VECTORS.POLICY.PUBLIC.001

**Vector Bucket Policy Must Not Permit Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

S3 Vectors Vector Bucket policies must not grant access to anonymous or wildcard principals. Vector Buckets use the s3vectors: IAM namespace, which is separate from s3:. Organization-level S3 Block Public Access and RCPs scoped to s3:* do not cover s3vectors: actions. A public policy on a Vector Bucket exposes vector indexes and the data they encode — embedding vectors can leak the semantic content of the source documents.

**Remediation:** Remove wildcard Principal statements from the Vector Bucket policy. Add aws:PrincipalOrgID condition. Verify SCP/RCP coverage for s3vectors: actions exists independently.

---


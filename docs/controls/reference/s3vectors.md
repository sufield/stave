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

### CTL.S3VECTORS.ENCRYPTION.001

**Vector Bucket Encryption Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.1;

S3 Vectors bucket does not have encryption configured. Vector embeddings encode semantic content of source documents — encryption at rest protects against unauthorized access to the underlying storage. S3 Vectors inherits the S3 encryption model but uses the s3vectors: IAM namespace, so S3 bucket-level encryption defaults do not apply to Vector Buckets.

**Remediation:** Enable SSE-KMS encryption on the Vector Bucket with a customer-managed KMS key. S3 Vectors encryption is set at bucket creation; for existing unencrypted buckets, recreate with encryption enabled and re-index.

---

### CTL.S3VECTORS.IAM.PUTVECTORS.WILDCARD.001

**IAM Policy Grants s3vectors:PutVectors With Wildcard Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6, AC-3; soc2: CC6.1, CC6.3;

An IAM policy grants s3vectors:PutVectors (or s3vectors:*) with Resource "*". This permits the principal to write embeddings to any vector index in the account. The s3vectors: namespace is separate from s3:, so policies restricting s3:PutObject do not constrain vector writes. A principal with wildcard PutVectors can poison any RAG pipeline's embeddings — the entire attack surface described in RAG poisoning research starts with this permission. The mitigation is a dedicated ingester role scoped to specific vector bucket and index ARNs.

**Remediation:** Scope the policy to specific vector bucket and index ARNs: "Resource": ["arn:aws:s3vectors:us-east-1:123456789012:bucket/rag-embeddings/index/product-catalog"]. Create a dedicated ingester role with only the indexes it needs to write. Remove s3vectors:PutVectors from shared roles, CI pipelines, and human users.

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


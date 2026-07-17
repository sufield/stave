# Control Reference — S3TABLES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.S3TABLES.ACCESS.EXTERNAL.001

**No Unauthorized External Access to Table Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Table Bucket policies must not grant access to external AWS accounts without organization-scoping conditions. The s3tables: IAM namespace is separate from s3:, so s3:-scoped RCPs that enforce data perimeters do not cover Table Buckets.

**Remediation:** Remove external account access or add aws:PrincipalOrgID condition. Verify s3tables:-scoped SCP/RCP coverage exists.

---

### CTL.S3TABLES.POLICY.CROSSACCOUNT.001

**Table Bucket Policy Must Restrict Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.3;

Table Bucket policies granting cross-account access must include an aws:PrincipalOrgID condition. The s3tables: namespace is separate from s3:, so RCPs scoped to s3:* that enforce PrincipalOrgID do not cover Table Buckets. An unscoped cross- account grant exposes Iceberg table data to external principals.

**Remediation:** Add aws:PrincipalOrgID condition to all Allow statements that grant access to external accounts.

---

### CTL.S3TABLES.POLICY.PUBLIC.001

**Table Bucket Policy Must Not Permit Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

S3 Tables Table Bucket policies must not grant access to anonymous or wildcard principals. Table Buckets use the s3tables: IAM namespace, which is separate from s3:. Organization-level S3 Block Public Access and RCPs scoped to s3:* do not cover s3tables: actions. A public policy on a Table Bucket exposes the entire Iceberg table catalog and data.

**Remediation:** Remove wildcard Principal statements from the Table Bucket policy. Add aws:PrincipalOrgID condition. Verify SCP/RCP coverage for s3tables: actions exists independently.

---


# Control Reference — GLACIER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GLACIER.ENCRYPT.CMK.001

**Glacier Vault Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Glacier vaults must use a customer-managed KMS key for encryption at rest instead of the AWS-managed default. Glacier encrypts all archives by default using SSE-S3 (AES-256), but the service-managed key has no customer-visible key policy and cannot be audited via CloudTrail KMS events. Archives stored in Glacier are typically long-term backups, compliance archives, or disaster-recovery copies — exactly the data that requires per-tenant key-policy control and the ability to revoke encryption access if the archive must be rendered unrecoverable.

**Remediation:** Glacier SSE cannot be changed on existing archives. To use a customer-managed key, migrate archives to S3 Glacier storage classes in an S3 bucket configured with SSE-KMS using a customer-managed key. Use S3 Batch Operations for bulk migration.

---

### CTL.GLACIER.POLICY.CROSSACCOUNT.001

**Glacier Vault Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Glacier vault access policy grants actions to principals in external AWS accounts without an aws:PrincipalOrgID condition. Glacier vaults store long-term archival data — backups, compliance records, and audit logs. Cross-account access without an org boundary means the external account can initiate retrieval jobs (glacier:InitiateJob), read archive contents (glacier:GetJobOutput), or delete archives (glacier:DeleteArchive). If the external account leaves the organization, access persists.

**Remediation:** Add an aws:PrincipalOrgID condition to restrict access to principals within the organization. For legitimate cross-org access, use explicit account ARNs and document the trust relationship.

---

### CTL.GLACIER.VAULT.POLICY.PUBLIC.001

**Glacier Vault Access Policy Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Glacier vault access policy grants actions to Principal "*" (any AWS account). Glacier vaults store long-term archival data — backups, compliance records, audit logs. A public vault policy lets any AWS account initiate retrieval jobs, read archive contents, or delete archives. Scott Piper's aws_exposable_resources lists glacier:SetVaultAccessPolicy as a public exposure vector. API: glacier:GetVaultAccessPolicy.

**Remediation:** Remove the wildcard principal from the vault access policy. Replace with explicit account ARNs and add an aws:PrincipalOrgID condition.

---


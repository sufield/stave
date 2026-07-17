# Control Reference — GLACIER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

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


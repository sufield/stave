# Control Reference — SECRET

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECRET.BLAST.001

**Secret with Multiple Readers Must Not Target Sensitive Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Secrets in Secrets Manager that provide credentials to sensitive resources (PHI, PII, confidential) must have a minimal set of readers. A secret readable by more than 3 principals is a high-value target — compromising any one of those principals provides a direct path to the sensitive data, bypassing IAM least privilege on the data resource itself. The extractor maps which principals have secretsmanager:GetSecretValue and which resource the secret unlocks.

**Remediation:** Reduce the number of principals with secretsmanager:GetSecretValue to the minimum required. Use resource-based policies on the secret to restrict access. Enable automatic rotation via aws secretsmanager rotate-secret --secret-id <id>.

---

### CTL.SECRET.BLAST.002

**Cross-Account Secret Access Must Not Target Sensitive Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

Secrets that provide credentials to sensitive resources must have access restricted to the owning account. Cross-account access to a secret that unlocks PHI or PII data doubles the blast radius — the secret is reachable from a wider set of principals across account boundaries.

**Remediation:** Remove cross-account access from the secret resource policy. If cross-account access is required, restrict to specific role ARNs and require an external ID condition.

---

### CTL.SECRET.BLAST.INCOMPLETE.001

**Complete Data Required for Secret Blast Radius Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Secret blast radius assessment requires the target_sensitivity field. The extractor could not determine which resource the secret provides credentials for.

**Remediation:** Tag secrets with the target resource ARN. Re-run the extractor with permissions to read secret metadata and tags.

---


# Control Reference — XRAY

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.XRAY.ENCRYPT.CMK.001

**X-Ray Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

X-Ray account encryption configuration does not use a customer- managed KMS key. X-Ray stores distributed traces containing request metadata, latency data, and potentially sensitive headers and annotations. Without Type set to KMS with a customer KeyId, traces use default encryption (Type NONE or AWS-managed).

**Remediation:** Set X-Ray encryption to KMS with a customer-managed key via PutEncryptionConfig (Type=KMS, KeyId=arn:aws:kms:...).

---

### CTL.XRAY.POLICY.CROSSACCOUNT.001

**X-Ray Resource Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-3, AC-4, AC-6; soc2: CC6.1, CC6.6;

X-Ray resource policy grants actions to principals in external AWS accounts without an aws:PrincipalOrgID condition. External accounts can read distributed traces containing request parameters, error details, latency data, and service topology. If the account leaves the organization, access persists. PutResourcePolicy controls cross-account trace collection and group access.

**Remediation:** Add aws:PrincipalOrgID restricting access to the organization's ID. For the rare legitimate cross-org grant, use aws:PrincipalAccount with the explicit account ID and document the trust relationship.

---


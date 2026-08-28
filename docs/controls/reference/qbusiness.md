# Control Reference — QBUSINESS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.QBUSINESS.APP.ENCRYPT.CMK.001

**Q Business Application Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Q Business application does not use a customer-managed KMS key. Applications store indexed enterprise documents, conversation history, and retrieval indices. Without a customer-managed key, encryptionConfiguration uses AWS-managed encryption with no customer-controlled key policy. Index-level encryption inherits from the application — no separate index KMS field exists.

**Remediation:** Create a new Q Business application with encryptionConfiguration.kmsKeyId set to a customer-managed KMS key. Existing applications cannot be re-encrypted.

---


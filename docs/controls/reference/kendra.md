# Control Reference — KENDRA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.KENDRA.INDEX.ENCRYPT.CMK.001

**Kendra Index Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Kendra index does not use a customer-managed KMS key. Kendra indexes store enterprise document content, metadata, and search indices. Without a customer-managed key, the index's ServerSideEncryptionConfiguration uses AWS-managed encryption with no customer-controlled key policy or CloudTrail key-usage logging.

**Remediation:** Create a new Kendra index with ServerSideEncryptionConfiguration.KmsKeyId set to a customer- managed KMS key. Existing indexes cannot be re-encrypted.

---


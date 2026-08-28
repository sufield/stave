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


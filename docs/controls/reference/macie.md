# Control Reference — MACIE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MACIE.ENABLED.001

**Amazon Macie Must Be Enabled for S3 Data Discovery**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Macie must be enabled for automated sensitive data discovery in S3 buckets. Without Macie, PII and sensitive data in S3 goes undetected.

**Remediation:** Enable Macie in the account.

---


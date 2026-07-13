# Control Reference — AMPLIFY

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AMPLIFY.APP.ACTIVE.001

**Amplify Apps Are Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active Amplify apps. Amplify provisions CloudFront distributions, S3 buckets, Lambda@Edge functions, and IAM roles behind a separate API surface — invisible to the standard CloudFront, S3, and Lambda management APIs and outside the organization's network security monitoring.

**Remediation:** Evaluate intent; if unwanted, delete apps and SCP deny amplify:*.

---


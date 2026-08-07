# Control Reference — ACCESSANALYZER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACCESSANALYZER.ENABLED.001

**IAM Access Analyzer Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, SI-4; soc2: CC7.2;

IAM Access Analyzer is not enabled. Access Analyzer identifies resources shared with external entities and validates IAM policies against best practices. Without it, unintended cross-account or public resource sharing goes undetected.

**Remediation:** Enable IAM Access Analyzer with an account or organization zone of trust to detect unintended resource sharing.

---


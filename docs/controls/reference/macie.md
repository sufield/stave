# Control Reference — MACIE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MACIE.CLASSIFICATION.001

**Macie Must Have Automated Sensitive Data Discovery Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; pci_dss_v4.0: 3.4.1; soc2: CC7.1;

Macie automated sensitive data discovery must be enabled. Basic Macie enablement (CTL.MACIE.ENABLED.001) activates the service but does not start scanning. Automated discovery continuously samples S3 objects across the account to find PII, financial data, and credentials without requiring manual classification job creation. Without automated discovery, sensitive data detection depends on manually-created jobs that may miss newly created buckets.

**Remediation:** Enable automated discovery: aws macie2 update-automated-discovery-configuration --status ENABLED

---

### CTL.MACIE.ENABLED.001

**Amazon Macie Must Be Enabled for S3 Data Discovery**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Macie must be enabled for automated sensitive data discovery in S3 buckets. Without Macie, PII and sensitive data in S3 goes undetected.

**Remediation:** Enable Macie in the account.

---


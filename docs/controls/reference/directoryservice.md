# Control Reference — DIRECTORYSERVICE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DIRECTORYSERVICE.ENABLED.001

**Directory Service Not Using Enterprise Edition**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

AWS Managed Microsoft AD directory is not using the Enterprise edition. For production hybrid AD environments, the Enterprise edition provides higher availability, more domain controllers, and trust relationship support required by the SRA shared services account pattern.

**Remediation:** For production workloads, create a new Enterprise edition directory: aws ds create-microsoft-ad --name corp.example.com --edition Enterprise.

---

### CTL.DIRECTORYSERVICE.LOGGING.001

**Directory Service Log Forwarding Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-2, AU-6; soc2: CC7.1;

AWS Managed Microsoft AD directory does not forward logs to CloudWatch. Without log forwarding, authentication events, group policy changes, and directory modifications are not available for security monitoring or incident investigation.

**Remediation:** Enable log forwarding: aws ds create-log-subscription --directory-id <dir-id> --log-group-name /aws/directoryservice/<dir-id>.

---


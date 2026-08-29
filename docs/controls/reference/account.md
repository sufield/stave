# Control Reference — ACCOUNT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACCOUNT.AI.UNSANCTIONED.001

**AI/ML Services Detected in Account Not Designated for AI Workloads**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, CM-8, AC-3; soc2: CC6.1, CC8.1;

AI/ML service resources detected in an account not designated for AI workloads. Shadow AI usage bypasses governance, security review, data classification, and cost controls. Teams scanning endpoints for AI artifacts nearly always find something they never sanctioned (Eric Doerr, Tenable). Unlike misconfigured AI (where an authorized service is set up incorrectly), shadow AI is unauthorized usage — the service should not exist in this account at all.

**Remediation:** Either authorize this account for AI workloads (add stave:ai-workload-authorized tag after security review) or decommission the unsanctioned AI resources. Investigate who provisioned them and whether data was processed.

---

### CTL.ACCOUNT.ANOMALY.MONITOR.001

**No Cost Anomaly Detection Monitor**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.2;

Account has no Cost Anomaly Detection monitor configured. Anomaly detection uses ML-based analysis to identify unusual spending patterns — the fastest automated detection path for denial-of-wallet attacks. Without it, the account relies on manual billing review or budget alerts (which fire only at fixed thresholds, not on anomalous patterns).

**Remediation:** Create a Cost Anomaly Detection monitor via the Cost Explorer API or console. Configure at least one subscription (SNS topic, email, or Lambda) to receive anomaly alerts.

---

### CTL.ACCOUNT.BUDGET.ALERT.001

**No AWS Budget With Alert Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.2;

Account has no AWS Budget with an alert notification configured. Without a budget alert, spending anomalies (including denial-of-wallet attacks via Marketplace subscriptions) are not detected until the next billing cycle — potentially days or weeks after the spend occurs.

**Remediation:** Create an AWS Budget with a cost threshold and configure at least one notification (SNS topic or email) to alert on actual or forecasted spend exceeding the threshold.

---

### CTL.ACCOUNT.DEPRECATED.SERVICE.001

**No Resources Must Exist for AWS-Deprecated Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-2, CM-8; soc2: CC6.1;

Resources exist for an AWS service that has been deprecated or announced for end-of-life. Resources on deprecated services are abandoned infrastructure by definition — the service they depend on is shutting down. AWS deprecated 15+ services in 2024-2025 including CodeCommit, Cloud9, SimpleDB, S3 Select, Data Pipeline, QLDB, Forecast, App Mesh, Lookout for Vision/Equipment, MediaStore, Elastic Transcoder, Honeycode, DeepComposer, DeepLens, and DeepRacer. Resources on these services receive no security patches and have no migration path after shutdown. Source: AWS breaking_changes repo (github.com/SummitRoute/aws_breaking_changes).

**Remediation:** Migrate resources off deprecated services before their end-of-support date. Decommission resources that are no longer needed. Inventory deprecated service resources via AWS Config or the service's own console.

---

### CTL.ACCOUNT.ENCRYPT.DEFAULT.PARITY.001

**Account Encryption Defaults Must Be Enabled Consistently**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Account-level default encryption is enabled for some storage services but not all. EBS default encryption may be on (CTL.EC2.EBS.DEFAULT.001) while RDS and EFS storage created in the same account is not encrypted by default. This is a PART OF gap: the account enforces encryption-at-rest defaults for one storage type but not others, so new resources created in unprotected services are unencrypted unless the creator explicitly enables encryption. The fix is to enable default encryption for all storage services at the account level so no new resource can be created without encryption.

**Remediation:** Enable default encryption for all storage services: - EBS: aws ec2 enable-ebs-encryption-by-default - RDS: aws rds modify-certificates (ensure new instances default to encryption) - EFS: enforce encryption via SCP or IaC policy Verify with aws ec2 get-ebs-encryption-by-default for EBS.

---

### CTL.ACCOUNT.POLLUTION.RATIO.001

**Account Has High Resource Pollution Ratio**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** nist_800_53_r5: CM-8, SI-12; soc2: CC7.1;

Account has a high ratio of unused or orphaned resources to active resources. Cloud pollution — stale access keys, orphaned security groups, unattached volumes, dormant Lambda functions — expands the attack surface without serving any workload. A high pollution ratio indicates insufficient lifecycle governance and increases the probability that an attacker finds an exploitable resource that no one is monitoring.

**Remediation:** Run a cloud pollution audit to identify stale access keys, orphaned security groups, unattached EBS volumes, dormant Lambda functions, and other unused resources. Delete resources that have no business justification. Implement lifecycle policies (DLM, Config rules) to prevent future accumulation.

---


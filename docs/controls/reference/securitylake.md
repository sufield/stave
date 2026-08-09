# Control Reference — SECURITYLAKE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECURITYLAKE.DELIVERY.HEALTH.001

**Security Lake Source Ingestion Must Be Healthy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-6; nist_800_53_r5: AU-6; pci_dss_v4.0: 10.3.1; soc2: CC7.2;

Security Lake source ingestion must be actively succeeding. Security Lake can be enabled with multiple AWS and custom sources configured while ingestion silently stops. When source ingestion fails, the OCSF-normalized data lake stops receiving new events — SIEM queries return stale results, subscriber pipelines process old data, and cross-account security analytics miss recent activity. The Security Lake console shows sources as "Enabled" but the underlying data pipeline has broken. This is the detection delivery pattern applied to the centralized security data lake.

**Remediation:** Check Security Lake source status and ingestion metrics. Common causes: S3 bucket policy modified, cross-account collection role revoked, Glue crawler failed, region removed from data lake configuration, or subscriber S3 notification event configuration was deleted. Re-establish source ingestion and verify by checking that new events appear in the data lake S3 prefix within the next collection interval.

---

### CTL.SECURITYLAKE.ENABLED.001

**Amazon Security Lake Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-6, SI-4; scs_c02: 10.8; soc2: CC7.1;

Amazon Security Lake is not enabled. Security Lake centralizes security data from AWS services, SaaS providers, and custom sources into a purpose-built data lake using the Open Cybersecurity Schema Framework (OCSF). Without it, security data is scattered across services and accounts, making cross-service correlation and long-term retention difficult.

**Remediation:** Enable Security Lake from the delegated admin account and configure log sources and rollup regions.

---

### CTL.SECURITYLAKE.ORG.NODELEGATED.001

**Security Lake Has No Delegated Administrator**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

Security Lake is managed from the management account because no delegated administrator is registered. Day-to-day Security Lake administration — managing log sources, subscribers, and rollup regions — concentrates operational footprint in the management account. AWS best practice is to delegate Security Lake administration to a dedicated log archive or security account.

**Remediation:** Register a log archive or security account as delegated admin: aws securitylake register-data-lake-delegated-administrator --account-id <log-archive-acct>.

---

### CTL.SECURITYLAKE.SOURCES.001

**Security Lake Missing Critical Log Sources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-3; scs_c02: 10.8; soc2: CC7.1;

Amazon Security Lake does not have all critical AWS log sources configured. Missing sources (CloudTrail, VPC Flow Logs, Route 53 DNS, Security Hub findings, Lambda, EKS audit, S3 data events) create visibility gaps in the centralized security data lake.

**Remediation:** Add missing log sources: aws securitylake create-aws-log-source --sources '[{"sourceName":"CLOUD_TRAIL_MGMT","regions":["us-east-1"]}]'.

---


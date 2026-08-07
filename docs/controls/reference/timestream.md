# Control Reference — TIMESTREAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TIMESTREAM.ARCHIVE.CONFIGURED.001

**Timestream Database Must Have Archive Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

Timestream database does not have data archival configured. Timestream data should be archived via scheduled queries to S3 for long-term retention beyond the magnetic store retention period.

**Remediation:** Configure scheduled queries to archive Timestream data to S3.

---

### CTL.TIMESTREAM.AUTH.ENDPOINT.001

**Timestream Endpoint Must Require Authentication**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

Amazon Timestream database endpoint does not require authentication. Without endpoint-level authentication, any client with network access can query or write time-series data.

**Remediation:** Configure the Timestream database to require IAM authentication for query and write access.

---

### CTL.TIMESTREAM.ENCRYPT.CMK.001

**Timestream Database Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Timestream databases must encrypt at rest with a customer-managed KMS key, not the AWS-owned default. Timestream encrypts all data by default using an AWS-owned key. Time-series data often includes IoT telemetry, application metrics, and operational data that may contain sensitive workload identifiers or behavioral patterns. The AWS-owned key cannot be audited, scoped, or revoked per tenant.

**Remediation:** Update the database KMS key using aws timestream-write update-database --kms-key-id with a customer-managed key ARN. Timestream supports in-place key changes.

---

### CTL.TIMESTREAM.LOG.AUDIT.001

**Timestream Audit Logging Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

Amazon Timestream database does not have audit logging enabled. Without audit logging, queries and writes to the time-series database are not recorded, limiting forensic capability.

**Remediation:** Enable audit logging for the Timestream database.

---


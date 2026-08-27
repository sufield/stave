# Control Reference — DMS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DMS.ENCRYPT.CMK.001

**DMS Replication Instance Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

DMS replication instance has encryption at rest enabled but does not use a customer-managed KMS key. The AWS-managed key provides at-rest encryption but no key-policy control and no ability to revoke access by disabling the key. If the uses_cmk field is absent the control is not-evaluable and does not fire.

**Remediation:** Create a new replication instance with a customer-managed KMS key (aws dms create-replication-instance --kms-key-id arn:aws:kms:...:key/...). Migrate tasks from the existing instance.

---

### CTL.DMS.ENCRYPT.REST.001

**DMS Replication Instance Storage Must Be Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

DMS replication instances must have storage encryption enabled. The replication instance holds source and target data in transit between databases — table mappings, cached rows, CDC change records, and LOB data. Without encryption at rest the instance's EBS volumes store this data in cleartext. An EBS snapshot taken for troubleshooting or shared cross-account exposes every row that passed through the replication.

**Remediation:** Encryption cannot be enabled on an existing replication instance. Create a new replication instance with KmsKeyId specified, migrate task definitions to the new instance, then delete the unencrypted instance.

---

### CTL.DMS.GHOST.TARGET.S3.001

**DMS Replication Target S3 Bucket Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, SC-28, SI-4; soc2: CC6.1, CC7.1;

DMS replication task is configured to replicate data to an S3 target endpoint whose bucket has been deleted. Replication fails or, if the bucket is re-registered, database records — potentially entire table contents — are written to attacker-controlled storage.

**Remediation:** Update the DMS S3 target endpoint to reference an existing bucket: aws dms modify-endpoint --endpoint-arn <arn> --s3-settings BucketName=<bucket>. Verify replication resumes.

---

### CTL.DMS.LOG.SOURCE.001

**DMS Replication Tasks Must Enable Source Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

DMS replication tasks must enable source logging (SOURCE_CAPTURE and SOURCE_UNLOAD) for auditability of data extraction from source databases.

**Remediation:** Enable SOURCE_CAPTURE and SOURCE_UNLOAD logging.

---

### CTL.DMS.LOG.TARGET.001

**DMS Replication Tasks Must Enable Target Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

DMS replication tasks must enable target logging (TARGET_APPLY and TARGET_LOAD) for auditability of data loading to target databases.

**Remediation:** Enable TARGET_APPLY and TARGET_LOAD logging.

---

### CTL.DMS.MULTIAZ.001

**DMS Replication Instances Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

DMS replication instances must enable Multi-AZ for cross-AZ standby redundancy during database migration and ongoing replication.

**Remediation:** Enable Multi-AZ on the replication instance.

---

### CTL.DMS.PUBLIC.001

**DMS Replication Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

DMS replication instances must not be publicly accessible. Public instances expose the migration pipeline to internet attacks, allowing data interception during database replication.

**Remediation:** Set PubliclyAccessible to false on the replication instance.

---

### CTL.DMS.ROLE.OVERBROAD.001

**DMS Replication Instance Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

DMS replication instance's IAM role has permissions beyond what database migration requires. DMS needs access to the specific source and target endpoints (database connections, S3 buckets for CDC targets, Kinesis streams for change capture) and CloudWatch Logs for task logging. Any action outside this set — s3:*, iam:PassRole, sts:AssumeRole on broad targets, rds:* — means a compromised DMS instance can access databases and storage beyond its replication scope. DMS instances sit between source and target data stores; an overbroad role grants cross-database access that should not exist.

**Remediation:** Scope the DMS role to the specific source and target endpoints, S3 buckets for CDC output, and CloudWatch Logs. Use separate roles for replication instances with different source-target pairs. Remove wildcard database and storage actions.

---

### CTL.DMS.SSL.001

**DMS Endpoints Must Enforce SSL/TLS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

DMS endpoints must use SSL/TLS (require, verify-ca, or verify-full) rather than none. Without SSL, data in transit between the replication instance and source/target databases is unencrypted.

**Remediation:** Set SslMode to require, verify-ca, or verify-full.

---

### CTL.DMS.UPGRADE.001

**DMS Replication Instances Must Enable Auto Minor Version Upgrade**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

DMS replication instances must enable automatic minor version upgrades to receive security patches during maintenance windows.

**Remediation:** Enable auto_minor_version_upgrade.

---


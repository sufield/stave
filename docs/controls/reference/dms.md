# Control Reference — DMS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

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


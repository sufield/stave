# Control Reference — BACKUP

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.BACKUP.ENCRYPT.001

**Backups Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; ffiec: BCP; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

All backups must be encrypted at rest. Unencrypted backups expose data if the backup storage is compromised or the backup is shared across accounts.

**Remediation:** Enable encryption on the backup vault or copy the backup with encryption enabled. For AWS Backup, set the vault encryption key to a customer-managed KMS key.

---

### CTL.BACKUP.EXISTS.001

**Critical Resources Must Have Backups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical or containing PHI must have at least one backup configured. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent and unrecoverable.

**Remediation:** Configure automated backups via AWS Backup, RDS automated snapshots, or S3 cross-region replication depending on the resource type.

---

### CTL.BACKUP.INCOMPLETE.001

**Complete Data Required for Backup Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

Backup safety cannot be assessed when backup status is missing from the snapshot. The extractor must populate backup.has_backup.

**Remediation:** Re-run the extractor with backup permissions: backup:ListBackupJobs, backup:DescribeBackupVault, rds:DescribeDBSnapshots, s3:GetBucketReplication.

---

### CTL.BACKUP.MULTIAZ.001

**Critical Resources Must Be Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Resources tagged as critical must be deployed across multiple Availability Zones. Single-AZ deployment has a single point of failure that causes unavailability during AZ outages.

**Remediation:** Enable Multi-AZ deployment or configure cross-AZ replication depending on the resource type (RDS Multi-AZ, S3 cross-region replication, ELB multi-AZ targets).

---

### CTL.BACKUP.PLAN.EXISTS.001

**AWS Backup Plan Must Exist and Cover Critical Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7)(ii)(A); mitre_attack: T1490; nist_800_53_r5: CP-9;

An AWS Backup plan must exist and protect critical resources. Without centralized backup, ransomware or accidental deletion can permanently destroy production data across EC2, RDS, EFS, DynamoDB, and S3.

**Remediation:** Create an AWS Backup plan covering all critical resources with daily backups and 35-day retention. Enable vault lock for write-once-read-many protection.

---

### CTL.BACKUP.RECENT.001

**Backups Must Be Recent**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** ffiec: BCP; hipaa: 164.308(a)(7); soc2: A1.1;

The most recent backup must be within the defined recovery point objective (RPO). Stale backups indicate a broken backup process and increase data loss exposure.

**Remediation:** Verify the backup schedule is active and producing successful backups. Check AWS Backup job history or RDS automated snapshot timestamps.

---

### CTL.BACKUP.RECOVERY.ISOLATION.001

**Backup KMS Key Must Be in Different Account Than Source Data**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: CP-9; nist_800_53_r5: CP-9; soc2: A1.1;

The KMS key used to encrypt backups must reside in a different AWS account than the source data. If both the data and the decryption key are in the same account, a single account compromise destroys both — the attacker can delete the data AND schedule the KMS key for deletion, rendering backups permanently unrecoverable.

**Remediation:** Create a dedicated backup recovery account. Generate a KMS key in the recovery account and use it for backup encryption. Use aws backup start-copy-job to replicate backups to the recovery account.

---

### CTL.BACKUP.RECOVERY.ISOLATION.002

**Data Admin Must Not Have KMS Key Deletion Permission**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: CP-9(1); nist_800_53_r5: CP-9(1); soc2: CC6.1;

The principal that administers the source data must have separate permissions from the principal that manages the backup encryption key. If the same admin can delete both the data and schedule the KMS key for deletion, a compromised credential enables complete and irreversible data destruction — the ransomware path.

**Remediation:** Separate data administration from key management. Use a dedicated backup admin role in a separate account. Apply SCP policies that deny kms:ScheduleKeyDeletion from data admin roles.

---

### CTL.BACKUP.REPLICATION.001

**Critical Data Must Have Cross-Region Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Data classified as critical or PHI must have cross-region replication configured for disaster recovery. Single-region data is vulnerable to regional outages and cannot meet recovery time objectives (RTO) for multi-region failover.

**Remediation:** Configure cross-region replication: S3 CRR, RDS cross-region read replica, or AWS Backup cross-region copy rule.

---

### CTL.BACKUP.VAULT.LOCK.001

**Backup Vaults Must Have Vault Lock Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.1;

AWS Backup vaults must have vault lock enabled to prevent deletion of recovery points. Without vault lock, an attacker with vault access can delete all backups before conducting a destructive attack — the ransomware pattern eliminates the recovery path before encrypting production data.

**Remediation:** Enable vault lock with a retention policy.

---


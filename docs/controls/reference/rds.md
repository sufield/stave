# Control Reference — RDS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.RDS.ALARM.CONNECTIONS.001

**RDS Instances Must Have a CloudWatch Alarm on DatabaseConnections**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

RDS instances must have a CloudWatch alarm configured on the DatabaseConnections metric. Connection exhaustion is the most common availability failure mode for managed databases, especially in workloads where Lambda functions connect directly (each cold start opens a new connection, and a cold- start storm can saturate max_connections in seconds). Once the connection limit is reached, the database refuses new connections with a "too many connections" error — the application's user-facing behavior is "intermittent inability to connect" rather than the kind of explicit database failure that the on-call response is rehearsed for, so the connection- exhaustion incident often runs longer than equivalent CPU-based incidents would. An alarm with a threshold around 80–90% of max_connections gives the on-call enough time to drain a misbehaving client before the saturation point.

**Remediation:** Create a CloudWatch alarm at 80–90% of max_connections with an SNS notification action.

---

### CTL.RDS.ALARM.CPU.001

**RDS Instances Must Have a CloudWatch Alarm on CPUUtilization**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

RDS instances must have a CloudWatch alarm configured on the CPUUtilization metric. CPU is the primary load signal a database publishes; sustained high CPU indicates one of a small set of conditions that all matter: a runaway query (application bug, missing index, unbounded recursion in a stored procedure), a connection storm (a misbehaving Lambda, a retry loop, or a DDoS), an SQL-injected cryptominer (documented multiple times in production environments — payloads that mine hash via expensive query operators), or a deliberate resource-exhaustion attack. The CloudWatch metric is published every minute whether or not anyone is watching; without an alarm the spike is visible only to whoever happens to be looking at the graph at the right time. The alarm is the only way the on-call engineer learns about the condition before the application's user-facing impact escalates the incident on its own.

**Remediation:** Create a CloudWatch alarm on AWS/RDS CPUUtilization with an SNS notification action.

---

### CTL.RDS.ALARM.REPLICATION.001

**RDS Instances With Read Replicas Must Alarm on ReplicaLag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: A1.2;

RDS instances that have read replicas (or are themselves read replicas) must have a CloudWatch alarm configured on the ReplicaLag metric. A read replica with growing lag serves stale data: every read directed to the replica returns rows as they existed at some bounded delta in the past, and the delta can drift from a few seconds to many minutes if the primary is under heavy write load or the replica's network is congested. Read-heavy applications routinely rely on read replicas without modeling the lag explicitly; the consistency assumption that feels free at low lag breaks at high lag in subtle, expensive ways: a user updates their billing address on the primary, refreshes the page, and the read against the replica returns the old value, which the user re-edits, generating a write/ read conflict the application cannot resolve cleanly. An alarm threshold tuned to the application's tolerance is the only way the team learns about the drift before customers do. The control fires only on instances that have or are read replicas; standalone instances have no ReplicaLag metric.

**Remediation:** Create a ReplicaLag alarm at the application's lag tolerance with an SNS notification action.

---

### CTL.RDS.ALARM.STORAGE.001

**RDS Instances Must Have a CloudWatch Alarm on FreeStorageSpace**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: A1.2;

RDS instances must have a CloudWatch alarm configured on the FreeStorageSpace metric. When an RDS instance exhausts its allocated storage, the database transitions to read-only: every write fails, in-flight transactions abort, and any application that depends on writing to the database errors out. If storage autoscaling is not also enabled, the only remediation is a manual storage modification, which can take minutes to commit and may require a maintenance-window-eligible reboot. Without an alarm the exhaustion is detected only by the application's first write failure, which is frequently the wrong place to discover the problem (a billing charge may have already failed, an idempotency key may have been consumed, an audit row may have been lost). An alarm at 10–20% free space gives the team hours of advance warning before exhaustion. This is the highest-severity alarm control because the failure mode is not "monitoring missed an attack" but "monitoring missed a self-inflicted outage."

**Remediation:** Create a FreeStorageSpace alarm at 10–20% free with an SNS notification action.

---

### CTL.RDS.AURORA.BACKTRACK.001

**Aurora MySQL Clusters Should Enable Backtrack**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

Aurora MySQL clusters should enable backtrack with a window appropriate to the workload's acceptable rewind distance (commonly 24–72 hours). Backtrack is Aurora MySQL's in-place point-in-time rewind: the cluster can be reset to any committed log point inside the backtrack window without restoring from snapshot, without provisioning a new cluster, and without disrupting consumers other than briefly pausing writes during the rewind. Without backtrack, recovery from destructive incidents the team caused itself — bad migration, wrong DELETE, dropped table, schema change that silently corrupted application invariants — requires restoring a snapshot to a fresh cluster (minutes-to-hours) and a cutover (minutes-to-hours of additional planning), during which the original cluster either keeps serving traffic against the corrupted state or stops serving altogether. Aurora MySQL only — Aurora PostgreSQL does not support backtrack and the control is gated to skip it.

**Remediation:** Enable backtrack with a window matching the workload's acceptable rewind horizon (24h is the published default ceiling unless explicitly raised).

---

### CTL.RDS.AURORA.GLOBAL.UNENCRYPTED.001

**Aurora Global Database Secondary Clusters Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4: 3.4;

Aurora Global Database secondary clusters must be encrypted at rest, and the destination-region KMS key must be authored by the same team that authored the primary's key (so that key-policy controls and rotation cadence apply uniformly to both regions). Aurora Global Database replicates committed changes from the primary cluster to one or more secondary clusters in other regions, with sub-second replication lag. When the secondary lands unencrypted, the same data that is encrypted at the primary is plaintext at the secondary — and the cross-region replication that motivated the Global Database deployment becomes the path that takes data out of encrypted storage. The most common origin of this gap is a CloudFormation copy of the primary cluster module that did not propagate the encryption configuration to the secondary, or a manual secondary-cluster creation that took the destination-region default and never set StorageEncrypted=true. The audit on the primary reads encrypted; the secondary is plaintext and never appears in the same audit query.

**Remediation:** Recreate the secondary with StorageEncrypted=true and a destination-region CMK; switch the Global Database failover target after verification.

---

### CTL.RDS.AURORA.SERVERLESS.V1.001

**Aurora Serverless v1 Clusters Must Migrate to v2**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-2;

Aurora clusters must not run Aurora Serverless v1; v2 (or the provisioned engine mode) is required. Serverless v1 carries a lengthy list of operational and security limitations that v2 closes: 30-second-class cold starts when scaling from zero, restricted engine version support (no current minor releases, no patches for some CVE windows), no read replicas, no Global Database, no IAM database authentication, no Performance Insights, and a scaling model that only steps in fixed power-of-two capacities. Each of those is a security-relevant gap as well as a performance one — the absence of IAM auth forces password-only authentication, the absence of Performance Insights removes the primary signal for SQL injection and cryptominer-via-query patterns, and the cold-start cliff produces availability behavior that alarms cannot smooth over. AWS has announced the v1 end-of-life schedule; clusters that have not migrated are on a deadline as well as carrying the limitations.

**Remediation:** Migrate the cluster to Aurora Serverless v2 or to provisioned engine mode before the v1 end-of-life deadline.

---

### CTL.RDS.AURORA.SINGLEINSTANCE.001

**Aurora Clusters Must Have More Than One Instance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

Aurora DB clusters must run with at least one writer plus one reader (or, more commonly, a writer plus two readers spread across AZs). A single-instance Aurora cluster has worse availability than a Multi-AZ standard RDS instance, not better: Multi-AZ RDS keeps a pre-provisioned standby ready to take over in seconds, while a single-instance Aurora cluster has nothing for Aurora to promote when the writer fails — it must provision a fresh instance on the surviving storage volume, an operation that takes minutes during which the cluster is unreachable. Aurora's architecture (storage-compute separation, six-way replicated storage, sub-second reader promotion) only delivers its availability premium when there is at least one reader to promote. The most common origin of this gap is a wizard- driven cluster creation that provisioned only the writer for cost reasons during initial bring-up, with a "we will add readers later" intention that never gets revisited.

**Remediation:** Add at least one reader instance, ideally in a different AZ from the writer.

---

### CTL.RDS.AUTH.MASTERPASSWORD.AGE.001

**RDS Master Password Must Be Rotated Within Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** hipaa: 164.308(a)(5)(ii)(D); nist_800_53_r5: IA-5; pci_dss_v4: 8.3;

RDS master passwords must be rotated at least every 90 days. The master password is the administrative credential — schema modification, user management, full data access, and configuration change all flow from it. Long-lived master passwords accumulate exposure across the lifetime of the organization: terminal sessions logged to shell history, config files committed to private-then-public repositories, connection pool definitions cached in build artifacts, Slack DMs and email threads from the database's initial setup, and team members who have rotated through the role and still have the credential in a password manager. Each individual exposure is small; the cumulative exposure of a 200-day-old password is significant and irreducible without rotation. The 90-day floor matches PCI-DSS 8.3 and FedRAMP credential-rotation expectations. Observable via the Secrets Manager secret's LastChangedDate when RDS uses ManageMasterUserPassword, or via CloudTrail ModifyDBInstance --master-user-password events otherwise.

**Remediation:** Rotate the master password (or enable Secrets Manager automatic rotation if using ManageMasterUserPassword).

---

### CTL.RDS.AUTH.MASTERUSER.001

**RDS Master Username Must Not Be a Common Default**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** nist_800_53_r5: IA-5; pci_dss_v4: 8.3;

RDS instances must not use a predictable master username such as admin, root, postgres, sa, master, dbadmin, mysql, or oracle. Predictable usernames hand the attacker half of the credential pair for free; brute-force, credential-stuffing, and password- spray campaigns target the well-known names first because they appear in every public account-enumeration wordlist. Unique per-fleet master usernames force the attacker to discover the username before any password attempt is meaningful, which moves the cost from "guess the password" to "first enumerate, then guess the password" and converts the attack from drive-by to targeted. The control is a defense-in-depth check: it does not replace strong passwords, MFA, or IAM authentication, but it removes the easy initial-access vector that public credential dumps and password-spray scripts assume.

**Remediation:** Recreate the database with a unique, non-guessable master username (instance recreation is required; ALTER USER cannot rename the master).

---

### CTL.RDS.AUTOUPGRADE.001

**RDS Auto Minor Version Upgrade Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.3.2; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: A1.1;

RDS instances must have automatic minor version upgrades enabled. Minor versions include security patches. Without auto-upgrade, instances run known-vulnerable database engine versions.

**Remediation:** Enable auto minor version upgrade: aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately

---

### CTL.RDS.BACKUP.001

**RDS Automated Backups Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

RDS instances must have automated backups enabled with a retention period of at least 7 days. Without backups, data loss from accidental deletion, corruption, or ransomware is permanent.

**Remediation:** Enable automated backups with at least 7 days retention. Run: aws rds modify-db-instance --db-instance-identifier xxx --backup-retention-period 7 --apply-immediately

---

### CTL.RDS.BACKUP.CROSSREGION.001

**RDS Instances Must Have a Cross-Region Recovery Path**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-6;

RDS instances must either replicate automated backups to a second region (AWS Backup cross-region copy or RDS automated backup replication) or carry a cross-region read replica that can be promoted on regional failover. RDS automated backups and manual snapshots are stored in the same region as the instance; without an explicit cross-region path, every recovery option is co-located with the resource it would recover. Regional outages are rare but documented (us-east-1 in 2017, 2020, 2021, and 2023; multiple-AZ outages have hit several regions in recent years), and when they occur they take the database AND its backups offline simultaneously. Multi-AZ alone does not address this — Multi-AZ failover occurs within the region. Cross-region DR is a risk-tolerance decision, not a technical impossibility: AWS Backup cross-region copy and RDS automated-backup replication are both first-class features. The control surfaces the absence so the decision is explicit (the team chose not to do it) rather than implicit (the team did not realize backups stay in-region).

**Remediation:** Configure cross-region automated backup replication or create a cross-region read replica.

---

### CTL.RDS.BACKUP.CROSSREGION.ENCRYPT.001

**RDS Cross-Region Backup Copies Must Be Encrypted at Destination**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4: 3.4;

RDS cross-region backup or snapshot copies must be encrypted at the destination region with a KMS key that exists in that region. Snapshot copy operations do not inherit the source region's KMS key — the destination must specify its own. If the copy is performed without `--kms-key-id`, the destination copy lands unencrypted (or, in rare permissions edge cases, the copy fails and falls back to retrying without the key). The result is a backup pair where the source-region copy is encrypted and the destination-region copy is not, and the next AWS Config audit reads "encrypted: yes" because it inspects the source instance, not the cross-region copy. Cross-region backups exist precisely because the team wants the data recoverable when the source region is unreachable; arriving at that recovery moment to find the destination copy unencrypted is the kind of "the alarm was disconnected from the bell" failure that compromises the recovery decision under outage pressure.

**Remediation:** Re-copy with an explicit destination-region KMS key (`--kms-key-id` on `copy-db-snapshot`).

---

### CTL.RDS.BACKUP.RETENTION.COMPLIANCE.001

**RDS Backup Retention Must Meet the Active Compliance Floor**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.316(b)(2)(i); nist_800_53_r5: CP-9; pci_dss_v4: 10.7;

RDS automated backup retention must meet the framework floor applicable to the data the instance handles: PCI-DSS 10.7 (1 year online, 1 year accessible offline; the operationally relevant floor is 365 days), HIPAA's 6-year audit retention under 164.316 (≈2190 days for the technical safeguards an RDS backup is taken to satisfy), SOX's 7-year retention for financial records (≈2555 days). The control is compliance- conditional: it fires when the instance carries a compliance tag (HIPAA, PCI, PII, FedRAMP, SOX, etc.) AND the retention is below the framework's floor. Operational-only retention (the basic "automated backups enabled" check) is covered by CTL.RDS.BACKUP.001; this control catches the gap between "backups exist" and "backups satisfy regulatory recovery windows." The remediation is either extending the automated- backup retention (capped at 35 days by RDS) or, more commonly, an AWS Backup vault with a lifecycle policy that matches the framework floor.

**Remediation:** Extend automated-backup retention or attach an AWS Backup vault with a framework-aligned lifecycle policy.

---

### CTL.RDS.CLUSTER.DELETION.PROTECT.001

**RDS Aurora Clusters Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** aws_security_hub: RDS.34; mitre_attack: TA0040; nist_800_53_r5: CP-9;

Aurora clusters without deletion protection can be permanently deleted via API or console without additional confirmation. Ransomware actors who gain IAM access with rds:DeleteDBCluster can destroy entire Aurora clusters including all instances and cluster storage. Deletion protection requires explicitly disabling the protection before deletion — breaking automated ransomware scripts.

**Remediation:** aws rds modify-db-cluster --db-cluster-identifier <id> --deletion-protection --apply-immediately

---

### CTL.RDS.CLUSTER.LOGGING.001

**RDS Aurora Clusters Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: RDS.36; mitre_attack: TA0005; nist_800_53_r5: AU-12;

RDS Aurora log export to CloudWatch Logs enables centralized log management, alerting on database errors, and retention beyond the default 7-day on-instance period. Without CloudWatch export, database audit logs, error logs, and slow query logs are only available via the RDS console for a limited period — making forensic investigation difficult after an incident.

**Remediation:** aws rds modify-db-cluster --db-cluster-identifier <id> --cloudwatch-logs-export-configuration EnableLogTypes=audit,error,slowquery --apply-immediately

---

### CTL.RDS.DELETEPROT.001

**RDS Instances Must Have Deletion Protection Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 2.3.3; nist_800_53_r5: CP-9;

RDS instances must have deletion protection enabled to prevent accidental or malicious database destruction. Without it, ransomware actors or misconfigured automation can permanently destroy production databases with a single API call.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately

---

### CTL.RDS.ENCRYPT.001

**RDS Storage Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.1; cis_aws_v3.0: 2.3.1; fedramp_moderate: SC-28; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

RDS instances must have storage encryption enabled. Unencrypted database storage exposes data at rest to unauthorized access if the underlying storage is compromised.

**Remediation:** Storage encryption can only be enabled at creation time. Create a snapshot, copy it with encryption enabled, then restore to a new encrypted instance. Enable encryption by default for new instances.

---

### CTL.RDS.ENCRYPT.BACKUP.001

**RDS Automated Backups Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4: 3.4;

RDS automated backups must be encrypted at rest. RDS automated backup encryption is bound to the source instance's encryption state at creation: an instance created without encryption stores its automated backups unencrypted, and re-enabling encryption on the live instance does not retroactively re-encrypt existing backups. This produces the surprising state where the live database appears encrypted in the console but a recoverable full copy of every committed transaction sits in the backup service unencrypted, accessible to anyone with rds:RestoreDBInstanceFromDBSnapshot rights. The unencrypted backup is identical in content to the encrypted live database; the security posture is whichever copy is easier to read. The control fires when the backup service reports backups are unencrypted regardless of the live instance's encryption flag, so the discrepancy surfaces explicitly instead of being hidden by the confidence the live-instance status creates.

**Remediation:** Recreate the instance from an encrypted snapshot copy and rotate the backup chain.

---

### CTL.RDS.ENCRYPT.CMK.001

**RDS Instances Should Be Encrypted with a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12;

RDS instances should be encrypted with a customer-managed KMS key (CMK), not the AWS-managed key (aws/rds). The aws/rds key is shared across every RDS instance in the account that did not specify a CMK; its key policy is AWS-controlled and cannot be modified, the key cannot be disabled in an emergency to revoke decrypt access, and snapshots encrypted with it cannot be shared cross-account (cross-account snapshot sharing requires a CMK). A customer-managed key delivers the four properties operators expect from "encryption with key control": the key policy is authored by the team (so decrypt access is bounded to specific principals), the key can be disabled to revoke access during incident response, the rotation schedule is configurable, and the key is portable for cross-account snapshot sharing. The data is encrypted under either key — the difference is whether the team controls the key.

**Remediation:** Re-encrypt the instance via snapshot/copy/restore using a CMK that the team controls.

---

### CTL.RDS.ENGINE.EOL.001

**RDS Instances Must Not Run End-of-Life Database Engine Versions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-2; hipaa: 164.312(c)(1); nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

RDS instances must not run major database engine versions that have reached end-of-life (EOL) and no longer receive security patches from the engine vendor. This is distinct from CTL.RDS.AUTOUPGRADE.001 which covers automatic minor version upgrades within a supported major version. Auto minor upgrade does not upgrade between major versions — an EOL major version receives no further patches regardless of the auto-upgrade setting. PostgreSQL 11 (EOL November 2023), MySQL 5.7 (EOL October 2023), and MariaDB 10.4 (EOL June 2024) are examples of major versions that continue running on RDS but receive no security patches from the upstream vendor. The engine version is permanently unpatched against any vulnerability disclosed after EOL. For PHI and cardholder data environments, running an EOL engine is a direct compliance finding — HIPAA requires maintained software and PCI-DSS 6.3.3 requires protection from known vulnerabilities through patching.

**Remediation:** Upgrade the RDS instance to a supported major engine version. For PostgreSQL, upgrade to PostgreSQL 14 or later. For MySQL, upgrade to MySQL 8.0. For MariaDB, upgrade to MariaDB 10.6 or later. Use a blue-green deployment or read replica promotion to minimize downtime. Test the application against the new major version in a staging environment before upgrading production — major version upgrades may include breaking changes in SQL behavior, function signatures, or default settings.

---

### CTL.RDS.EVENTS.001

**RDS Must Have Event Subscriptions for Critical Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12;

RDS instances must have event subscriptions configured for critical event categories. RDS event subscriptions notify operators of configuration changes, failovers, security group modifications, and parameter group changes. Without event subscriptions, critical changes to database instances go undetected — an attacker who modifies security groups, disables encryption, or changes authentication settings generates no alert. RDS events are the primary detection mechanism for unauthorized database configuration changes. Event subscriptions are not enabled by default and must be explicitly created for each event category. The absence of event subscriptions creates a detection gap where database-level security changes occur without any notification to the security team.

**Remediation:** Create RDS event subscriptions for critical event categories including configuration change, failover, failure, maintenance, and security group. Subscribe to an SNS topic that routes to the security monitoring pipeline. At minimum, create subscriptions for the db-instance source type with the configuration change and security categories enabled.

---

### CTL.RDS.EVENTS.DELETION.001

**RDS Must Have Event Subscription for Deletion Events**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.2;

An RDS event subscription must be configured to notify on instance deletion (event categories including "deletion" or "configuration change" depending on engine). Deletion protection (CTL.RDS.DELETEPROT.001) is the preventive control; the event subscription is the detective control that catches any case where deletion protection was disabled — by drift, by a maintenance task that disabled it temporarily and forgot to re-enable, or by an authorized but uncoordinated change. Without an event subscription, a deletion that succeeds produces no real-time signal; the database is gone, and the team learns about it from the application's failure mode rather than from the deletion event itself. RDS event subscriptions integrate with SNS for fan-out to email, SMS, Slack, PagerDuty, and SIEM ingestion. Distinct from CTL.RDS.EVENTS.001 (the generic "any critical subscription" check); this control specifically requires the deletion category.

**Remediation:** Create an RDS event subscription that includes the deletion category and routes to SNS.

---

### CTL.RDS.EVENTS.SECURITY.001

**RDS Must Have Event Subscription for Security Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-12; pci_dss_v4: 10.2;

An RDS event subscription must be configured to notify on security-relevant events: security group association changes, parameter group changes, configuration changes, and certificate changes. These categories cover every modification that shifts the instance's security posture — and every one of them deserves a real-time signal even when the change is authorized, because the audit trail is the cheapest evidence the organization will get that the change happened. Without the subscription, security-posture changes are visible only in CloudTrail (which is correct, but not real-time and not routed to the on-call channel). The subscription pushes the same events to SNS as soon as they fire, so an unintended change — a security group swapped to an open one during a rushed migration, a parameter group switched to default by a wizard, a certificate rotation that did not complete — is detected during the change rather than during the next audit pass. Distinct from CTL.RDS.EVENTS.001 (generic) and CTL.RDS.EVENTS.DELETION.001 (specifically deletion).

**Remediation:** Add security-related categories (security, configuration change, parameter, certificate) to an RDS event subscription.

---

### CTL.RDS.GHOST.EVENTSNS.001

**RDS Event Subscriptions Must Not Target Deleted SNS Topics**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.2;

RDS event subscriptions must publish to SNS topics that currently exist. The subscription persists after its target SNS topic is deleted: the RDS API still records an active subscription, the console still lists it as enabled, and RDS continues to generate the configured event categories (deletion, configuration change, failover, parameter changes, security events). The events are published into the deleted topic and silently dropped. The team operates under the assumption that the on-call channel will see deletion events, failovers, security-posture changes — and none of them arrive. Same pattern as the existing CTL.CLOUDWATCH.ALARM.GHOST.001 control (CloudWatch alarm action targeting a deleted SNS topic): both reflect SNS-topic decommissioning without updating the consumers. The control catches it at the RDS side specifically because the alarm-side check does not cover RDS event subscriptions.

**Remediation:** Update the subscription to a current SNS topic or delete the orphaned subscription.

---

### CTL.RDS.GHOST.OPTIONGROUP.001

**RDS Instances Must Not Reference Deleted Option Groups**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

RDS instances must reference option groups that currently exist. Option groups configure the engine-specific feature set that the application depends on: Oracle TDE (transparent data encryption), SQL Server audit specifications, MySQL backtrack, S3 integration for backups, custom listener ports, and certificate-trust extensions. When the option group is deleted, the features it enabled silently revert. Oracle TDE-protected tables become unencrypted at the engine layer (data on disk is still EBS-encrypted, but the column-level protection is gone). SQL Server audit may stop emitting records. The instance continues serving traffic; the option-group-driven feature set has changed without any visible signal in the RDS console. Engine-specific compliance posture (FIPS modules, FedRAMP feature-flag requirements, customer-contractual TDE clauses) may quietly fall out of conformance.

**Remediation:** Recreate the option group with the intended options or migrate the instance to an existing equivalent group.

---

### CTL.RDS.GHOST.PARAMGROUP.001

**RDS Instances Must Not Reference Deleted Parameter Groups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; pci_dss_v4: 2.2;

RDS instances must reference parameter groups that currently exist and are in the in-sync state. The parameter group governs every engine setting that the security review depends on: force_ssl / require_secure_transport (TLS enforcement), log_statement / log_connections (audit logging), password_encryption (PostgreSQL hash algorithm), and dozens more. When the parameter group is deleted (or stuck in an inconsistent / pending-restart state), the instance falls back to engine defaults — typically the AWS default group, which is permissive by design (TLS not enforced, statement logging off, md5 passwords on PostgreSQL). The instance keeps running. The RDS console shows the instance healthy. But the security configuration the team authored has silently reverted. The failure is invisible: the only signal is that the next audit reads completely different parameter values than the team expects. The control catches the reference at the inventory level so the silent degradation surfaces immediately.

**Remediation:** Recreate the parameter group with the intended settings or point the instance at an existing equivalent group.

---

### CTL.RDS.GHOST.PROXYSECRET.001

**RDS Proxies Must Not Reference Deleted Secrets Manager Secrets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** nist_800_53_r5: CM-2; pci_dss_v4: 8.2;

RDS Proxies must reference Secrets Manager secrets that currently exist. The Proxy authenticates to its backend database using credentials retrieved from Secrets Manager; when the secret is deleted, the Proxy keeps serving the connection pool it has already authenticated, but every new connection (pool growth, pool refresh after idle expiry, scale-out, restart) requires re-fetching the secret and fails. The failure mode is the most dangerous one in the ghost-reference family: it is delayed, not immediate. The Proxy console reports healthy. The application sees normal traffic. Hours later — frequently in the off-hours when the pool naturally turns over — a wave of connection failures surfaces, with no obvious link to the secret deletion that happened earlier in the day. Proxy-secret ghosts are particularly common after secret-rotation workflows that delete the previous secret without confirming the Proxy was actually pointed at the new one. The control fires on the reference at audit time so the failure is paid in change-window time rather than during incident time.

**Remediation:** Point the Proxy at the current secret (or restore the secret if deletion was unintentional and within the recovery window).

---

### CTL.RDS.GHOST.SG.001

**RDS Instances Must Not Reference Deleted Security Groups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: CM-2; pci_dss_v4: 1.2;

RDS instances must reference security groups that currently exist in the VPC inventory. When an attached SG is deleted, the instance's effective network policy becomes undefined: AWS removes the deleted SG from the attachment list at the next modification, but until then the instance is operating with a rule set that no longer reflects what the security review authored. In practice three failure modes are seen on this pattern. (1) The team that owns the SG decommissions it believing nothing references it; the database keeps running on the residual rules until the next modification reconciles the list. (2) The SG is replaced by a successor; the instance was never re-pointed and falls back to whatever default is applied. (3) An infrastructure-as-code drift removes the SG from the configuration without removing the attachment from the database resource. Distinct from the existing CTL.VPC.SG.GHOST.001 (which checks SG-rule-to-SG references); this control checks RDS-instance-to-SG references.

**Remediation:** Detach the deleted SG and attach a current SG that encodes the intended network policy.

---

### CTL.RDS.GHOST.SUBNETGROUP.001

**RDS DB Subnet Groups Must Not Reference Deleted Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: A1.2;

RDS DB subnet groups must reference only subnets that currently exist in the VPC inventory. The DB subnet group is the placement pool the engine uses for Multi-AZ failover and read-replica positioning: when failover triggers, RDS picks an availability-zone target from the group and provisions the standby in a subnet from that AZ. A subnet that has been deleted (typically by a network refactor that did not coordinate with the database team) leaves the group with fewer placement options than the failover policy assumes. The group still looks valid in the console and the primary continues running, so the ghost is invisible until the moment failover is needed — at which point RDS attempts to place the standby in a subnet that does not exist and the failover fails. The control surfaces the ghost preemptively so the cleanup is paid in change-window time rather than during an AZ outage.

**Remediation:** Remove the deleted subnets from the subnet group; replace with current subnets in the same AZs.

---

### CTL.RDS.HA.REPLICA.CONFIG.001

**RDS Read Replicas Must Match Their Primary's Security Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; pci_dss_v4: 1.2;

RDS read replicas must inherit (or precisely match) the source instance's security configuration: security group attachments, parameter group, encryption at rest setting, and PubliclyAccessible flag. The replica serves the same rows as the primary; if its security configuration is weaker, the replica becomes the path of least resistance to the same data. Three drift patterns are seen in the field. (1) Replica with a broader security group than the primary (someone allowed broader CIDRs to the replica for reporting/BI access and never tightened them again). (2) Replica with a different parameter group that has TLS enforcement off, audit logging off, or password hashing weak — the replica accepts plaintext connections and password-spray that the primary refuses. (3) Replica with PubliclyAccessible=true while the primary is private — introducing an internet-reachable copy of the production data. The control fires on any of these drift conditions and the finding lists the specific differences so the remediation can target only what actually drifted.

**Remediation:** Reconcile the replica's SG, parameter group, encryption, and PubliclyAccessible settings to match the primary.

---

### CTL.RDS.HA.REPLICA.SAMEAZ.001

**RDS Read Replicas Must Be in a Different AZ Than Their Primary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

RDS read replicas must be placed in a different availability zone from their primary instance. A replica in the same AZ provides read-traffic scaling but no AZ-level redundancy: any AZ-level event (the most common AWS outage class — a single AZ losing power, network, or control-plane reachability) takes both the primary and the replica down simultaneously. The replica's value proposition is twofold: read scaling AND failover resilience. Same-AZ placement collapses the second half. Multi-region read replicas (where allowed by engine and workload) provide stronger isolation, but at minimum the replica should sit in a different AZ in the same region. The most common origin of this gap is a hurried wizard flow where the replica defaulted to the primary's AZ and the operator did not change it, or an IaC apply that placed both into the same subnet group AZ because the group only had one AZ configured.

**Remediation:** Recreate the replica in a different AZ (or in a different region for stronger isolation).

---

### CTL.RDS.IAMAUTH.001

**RDS Must Enable IAM Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d);

RDS instances should enable IAM database authentication. IAM auth eliminates long-lived database passwords and integrates with AWS identity governance for centralized access control and audit.

**Remediation:** Enable IAM authentication on the instance. Run: aws rds modify-db-instance --db-instance-identifier xxx --enable-iam-database-authentication --apply-immediately

---

### CTL.RDS.INCOMPLETE.001

**Complete Data Required for RDS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

RDS instance safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate database.encryption.storage_encrypted.

**Remediation:** Re-run the extractor with RDS permissions: rds:DescribeDBInstances, rds:DescribeDBClusters.

---

### CTL.RDS.LIFECYCLE.GENERATION.001

**RDS Instances Should Use Current-Generation Instance Classes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-2;

RDS instances should run on a current-generation instance class. Older RDS instance families — db.m4, db.r4, db.t2, db.m3, and earlier — sit on Xen-based hypervisor hardware and lose access to several Nitro-only protections that the newer Graviton (db.m7g, db.r7g, db.t4g) and Nitro-x86 (db.m6i, db.r6i) families enable. Three properties matter: the historical Xen XSA CVE class continues to apply to the older families (the same hypervisor surface that CTL.EC2.NITRO.001 catches on EC2 — RDS runs the same underlying hosts), the newer families have meaningfully better performance per dollar (commonly 20-40% on Graviton), and AWS instance-family lifecycle eventually retires the oldest classes from regions, leaving instances on those families unable to scale, modify, or recover via failover. Migration to a current generation is an in-place modification — no data move, no application reconfiguration — so the cost is small and the upside spans security (Nitro), performance, and longevity.

**Remediation:** Modify the instance class to a current-generation family (db.m7g, db.r7g, db.t4g, or current-gen Nitro-x86).

---

### CTL.RDS.LIFECYCLE.STORAGETYPE.001

**RDS Instances Should Use gp3 Storage Instead of Legacy gp2**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

RDS instances should use gp3 storage rather than the legacy gp2 storage type. gp3 is the current general-purpose SSD option and provides three properties gp2 does not: a baseline 3000 IOPS regardless of volume size (gp2 IOPS scales with size at 3 IOPS/GB and credits-balance under burst, producing latency cliffs the application experiences as request stalls), independently provisionable IOPS and throughput (so the team can size for application-actual numbers rather than buying capacity to obtain IOPS), and lower per-GB storage cost at equivalent performance. Migration is online — RDS performs the storage-type modification without downtime and without dropping connections. The security relevance is indirect but real: gp2's burst-credit exhaustion produces availability-affecting latency spikes that incident response often misattributes to application bugs, and the presence of legacy gp2 signals an instance that has not been touched by recent hardening cycles.

**Remediation:** Modify the instance to gp3 storage (online; no downtime); review IOPS/throughput against application-actual numbers.

---

### CTL.RDS.LOG.001

**RDS Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

RDS instances must export audit logs to CloudWatch. Without audit logging, database access patterns cannot be monitored and unauthorized queries are undetectable.

**Remediation:** Enable CloudWatch log exports for the database engine. Run: aws rds modify-db-instance --db-instance-identifier xxx --cloudwatch-logs-export-configuration '{"EnableLogTypes":["audit","error","slowquery"]}'

---

### CTL.RDS.LOG.RETENTION.001

**RDS CloudWatch Log Group Retention Must Meet Compliance Floor**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.316(b)(2)(i); nist_800_53_r5: AU-11; pci_dss_v4: 10.7;

CloudWatch log groups receiving RDS database logs must have a retention policy of at least 365 days (or whatever framework ceiling the workload sits under: HIPAA frequently requires 6 years for audit-relevant logs; PCI-DSS 10.7 specifies 1 year online and 1 year accessible; SOX commonly mandates 7 years). Two failure modes converge on this control. First, a log group with no retention policy at all retains logs indefinitely — a cost issue and, in some jurisdictions, a privacy / data- minimization issue (logs containing PII linger past the workload's actual retention obligation). Second, and more commonly, a log group with a default short retention (a few weeks) discards database audit data well before the framework retention window, so any post-incident investigation that begins more than a month after the relevant access cannot recover the audit record. The control fires when the retention setting falls outside the configured acceptable range.

**Remediation:** Set the log group retention to at least 365 days (or your framework ceiling).

---

### CTL.RDS.LOG.SLOWQUERY.001

**RDS Slow Query Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2; pci_dss_v4: 10.2;

RDS instances must enable slow-query logging at the engine- appropriate parameter (`slow_query_log = 1` for MySQL/MariaDB; `log_min_duration_statement` set to a positive millisecond value, not -1, for PostgreSQL; equivalent for SQL Server / Oracle). Slow-query logs do triple duty for security and reliability: they are the primary signal for performance degradation that the application has not yet escalated, they are a strong indicator of SQL injection (injected payloads often produce execution plans that fall outside the normal query distribution and trip the slow threshold), and they surface deliberate denial-of-service patterns (intentionally expensive queries that hold connections and consume CPU). Without slow-query logging the database silently absorbs the cost of pathological queries and the only signal the organization gets is general latency — too dull to attribute back to a specific actor or query. The control fires when the engine-appropriate slow-query parameter is off.

**Remediation:** Enable the engine-appropriate slow-query parameter (slow_query_log for MySQL, log_min_duration_statement for PostgreSQL).

---

### CTL.RDS.MINOR.UPGRADE.001

**RDS Instances Must Enable Automatic Minor Version Upgrades**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: RDS.13; mitre_attack: TA0003; nist_800_53_r5: SI-2;

Minor version upgrades contain security patches for the database engine. Disabling automatic minor upgrades means security patches require manual intervention — patches are commonly delayed or forgotten, leaving the database engine vulnerable to known CVEs. Minor upgrades are backwards-compatible by design and the maintenance window controls when they apply.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately

---

### CTL.RDS.MONITORING.001

**RDS Enhanced Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; hipaa: 164.312(b); nist_800_53_r5: SI-4; soc2: CC7.1;

RDS instances must have Enhanced Monitoring enabled. Enhanced Monitoring provides real-time OS-level metrics (CPU, memory, disk I/O, network) that standard CloudWatch metrics do not capture. Without it, performance degradation and resource exhaustion attacks are harder to detect and investigate.

**Remediation:** Enable Enhanced Monitoring with a 60-second granularity. Run: aws rds modify-db-instance --db-instance-identifier xxx --monitoring-interval 60 --monitoring-role-arn arn:aws:iam::ACCOUNT:role/rds-monitoring-role --apply-immediately

---

### CTL.RDS.MONITORING.INTERVAL.001

**RDS Enhanced Monitoring Interval Must Not Exceed 15 Seconds**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

RDS Enhanced Monitoring must collect at intervals of 15 seconds or shorter when enabled. Enhanced Monitoring delivers OS-level metrics (CPU, memory, disk I/O, process and thread counts, network bytes) that are unavailable from the standard CloudWatch metrics, and the value of those metrics for incident detection is bounded by the sampling rate. At 60-second intervals — the default option in many wizard-driven setups — short-duration events (a 30-second connection storm, a 20-second runaway query, a 45-second OOM-and-recover cycle) fall entirely between collection points and are invisible to subsequent investigation. The investigation reads "metrics looked normal" and concludes the database was healthy when the workload saw it stutter. 15-second granularity is the published recommendation for databases that take production traffic. Distinct from CTL.RDS.MONITORING.001 which checks that Enhanced Monitoring is enabled at all.

**Remediation:** Modify the instance to set the Enhanced Monitoring interval to 15 seconds (or shorter).

---

### CTL.RDS.MULTIAZ.001

**RDS Instances Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: A1.1;

Production RDS instances must use Multi-AZ deployment for high availability. Single-AZ instances have a single point of failure that can cause data unavailability during AZ outages.

**Remediation:** Modify the instance to enable Multi-AZ. Run: aws rds modify-db-instance --db-instance-identifier xxx --multi-az --apply-immediately

---

### CTL.RDS.ORPHAN.SNAPSHOT.001

**RDS Snapshots Must Not Persist Past Their Source Instance**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.310(d)(2)(i); nist_800_53_r5: MP-6; pci_dss_v4: 9.4;

RDS snapshots whose source DB instance has been deleted should be removed (or their retention deliberately documented). When an RDS instance is deleted, AWS optionally creates a "final-snapshot" capturing the full database state, and any manual snapshots taken during the instance's lifetime continue to exist. The instance is decommissioned in the inventory; the data is not. The snapshot contains every committed table, every stored procedure, every user account in the engine's auth catalog (with password hashes), and any application secrets the team stored in config tables. Anyone with rds:RestoreDBInstanceFromDBSnapshot rights — and there are usually more such principals than the team has audited recently — can restore the snapshot to a fresh instance and read the entire historical database. The snapshot is rarely the artifact security review focuses on, because the instance it came from is "gone." Long-lived orphan snapshots are the primary path by which decommissioned-database content resurfaces months or years later.

**Remediation:** Delete the orphan snapshot (or document retention policy that requires keeping it).

---

### CTL.RDS.ORPHAN.SUBNETGROUP.001

**RDS DB Subnet Groups Must Be Used by at Least One Instance**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance

RDS DB subnet groups should be associated with at least one active RDS instance or cluster. An orphan subnet group is the catalog-level signal that a database was decommissioned without the cleanup workflow reaching the supporting infrastructure: the instance is gone, the subnet group remains, and frequently the instance's parameter group, option group, and final snapshot remain alongside it. Orphan subnet groups also retain references to the underlying VPC subnets and may pin those subnets in place during a network refactor (the subnets cannot be deleted while a subnet group references them). Cleaning the subnet group is part of finishing decommissioning; the organization gets visibility into which decommissions stopped short of completion. The control is low-severity by itself because a stray subnet group does not directly leak data — but in combination with an orphan snapshot or a ghost parameter group it reveals a systematic gap in the decommissioning runbook.

**Remediation:** Delete the orphan subnet group or document why it must be retained.

---

### CTL.RDS.PARAM.GROUP.001

**RDS Instances Must Not Use the Default Parameter Group**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: RDS.19; mitre_attack: TA0005; nist_800_53_r5: CM-6;

The default RDS parameter group uses AWS-managed settings that cannot be audited for security-relevant configuration. A custom parameter group enables enforcing SSL/TLS enforcement, audit logging parameters, and password validation plugins. Without a custom parameter group, these security settings cannot be verified or enforced via configuration snapshots.

**Remediation:** Create a custom parameter group and attach it to the instance. Then set security parameters such as require_secure_transport=ON for MySQL or rds.force_ssl=1 for PostgreSQL.

---

### CTL.RDS.PARAM.LOGEXPORT.001

**RDS Instances Must Export Logs to CloudWatch Logs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4: 10.2;

RDS instances must populate EnabledCloudWatchLogsExports with the engine-appropriate log types (postgresql + upgrade for PostgreSQL; audit + error + general + slowquery for MySQL; audit + error + agent + trace for SQL Server; alert + audit + listener + trace for Oracle). Logs that remain on the RDS instance are accessible only via the RDS console and the DescribeDBLogFiles API; they are not searchable across the fleet, not subscribable to CloudWatch Alarms, not exportable to a SIEM via subscription filter, and they disappear when the instance is deleted or when the RDS log rotation cycles them out. Exporting logs to CloudWatch Logs makes them addressable by the same observability and incident-response tooling the rest of the account uses: log group permissions are managed by IAM, retention is independent of the instance lifecycle, metric filters and alarms work, and the existing SIEM subscription pipelines pick them up. This control checks the instance's top-level log-exports list (a property of the instance, not the parameter group), distinct from CTL.RDS.CLUSTER.LOGGING.001 which covers the same gap on Aurora clusters.

**Remediation:** Set EnabledCloudWatchLogsExports to the engine-appropriate log types.

---

### CTL.RDS.PARAM.PASSWORDHASH.001

**PostgreSQL RDS Instances Must Use scram-sha-256 Password Hashing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: IA-5; pci_dss_v4: 8.3;

PostgreSQL RDS instances must set the password_encryption parameter to scram-sha-256, not md5. MD5 password hashing on PostgreSQL is unsalted (a static deterministic hash of the password and the username), which makes large-scale rainbow table lookups effective against any database whose pg_authid contents leak — a scenario that includes routine pg_dump artifacts, replication snapshots, and cross-account snapshot sharing. scram-sha-256 (RFC 5802 / RFC 7677, supported since PostgreSQL 10) introduces per-user salts, iterative hashing, and a challenge-response authentication exchange that does not expose the password hash to the network. The parameter governs every new password set after the change; existing MD5 hashes are converted on the next password rotation. The control fires only on PostgreSQL engines (a no-op for MySQL / SQL Server / Oracle).

**Remediation:** Set password_encryption to scram-sha-256 in the parameter group and rotate user passwords.

---

### CTL.RDS.PERFINSIGHTS.RETENTION.001

**Performance Insights Retention Must Be At Least 7 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-11; soc2: CC7.2;

Performance Insights retention on RDS instances must be set to at least 7 days (the free-tier ceiling). Retention shorter than 7 days collapses the historical query-performance window to a size that does not support routine workflows: trend analysis across a release cycle becomes impossible, regression detection after a deploy cannot reach back to the pre-deploy baseline, and post-incident investigations that begin more than a few hours after the fact find the relevant Top SQL data already aged out. The 7-day floor is free; longer retention (24 months) is paid but commonly worth it on production systems. Distinct from CTL.RDS.PERFORMANCE.INSIGHTS.001 which checks that PI is enabled and KMS-encrypted at all.

**Remediation:** Modify the instance to set Performance Insights retention to at least 7 days.

---

### CTL.RDS.PERFORMANCE.INSIGHTS.001

**RDS Instances Must Have Performance Insights Enabled with KMS Encryption**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: RDS.17; mitre_attack: TA0005; nist_800_53_r5: AU-12;

Performance Insights captures database query patterns and wait events. When encrypted with a customer-managed KMS key, this data is protected and provides an additional audit source for database activity. Without Performance Insights, slow or anomalous queries such as bulk data extraction may not be visible in standard database logs.

**Remediation:** aws rds modify-db-instance --db-instance-identifier <id> --enable-performance-insights --performance-insights-kms-key-id <key-arn> --performance-insights-retention-period 731 --apply-immediately

---

### CTL.RDS.PROXY.EXPOSURE.001

**RDS Proxies Must Not Be Reachable Beyond the Application Tier**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; pci_dss_v4: 1.4;

RDS Proxy security groups must restrict ingress to the application-tier sources that need database access — not management subnets, not public subnets, not cross-VPC CIDRs that the Proxy was never intended to serve. The Proxy is the entry point to the backend database; its ingress policy is what decides which principals can attempt a connection through it, and any over-broad rule in that policy bypasses every authentication, encryption, and audit improvement the Proxy was deployed to provide. The Proxy's own auth (CTL.RDS.PROXY.IAM.001) and TLS (CTL.RDS.PROXY.TLS.001) defenses still apply, but unnecessary network reachability turns the Proxy into a high-visibility credential-test target — every IAM principal anywhere with rds-db:connect against the Proxy ARN can attempt connections, and the audit log fills with attempted-but-denied connections from places that should never have been able to reach the Proxy at all.

**Remediation:** Tighten the Proxy's SG to allow only the application subnets / CIDRs that need database access.

---

### CTL.RDS.PROXY.IAM.001

**RDS Proxies Must Require IAM Authentication for Client Connections**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** nist_800_53_r5: IA-2; pci_dss_v4: 8.2;

RDS Proxies must set ClientAuthType / RequireTLS-and-IAM such that client connections present an IAM authentication token, not a static database password. Without IAM auth at the Proxy the application authenticates to the Proxy with the same username/password it would have used directly against the database — defeating one of the principal reasons to deploy the Proxy in the first place (centralizing credential handling away from the application). With IAM auth required, clients generate a short-lived auth token via rds-db:connect (15-minute lifetime) using their own IAM identity; the Proxy validates the token, then uses the Secrets-Manager-managed backend credential to talk to the database. The application no longer holds the database password at all. Authentication, authorization, and audit all flow through IAM, the same mechanism that controls every other AWS access on the account.

**Remediation:** Set the Proxy's auth scheme to require IAM (RequireIAM=true on the auth descriptor).

---

### CTL.RDS.PROXY.TLS.001

**RDS Proxies Must Require TLS to the Backend Database**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4: 4.1;

RDS Proxies must require TLS for the backend connection from Proxy to RDS instance, not only for the client-to-Proxy hop. The Proxy is a connection terminator: it accepts client connections (commonly TLS-encrypted), then opens its own separate connections to the backend database from a managed pool. If the backend connections are not TLS, the Proxy-to- database hop is plaintext — including the database password retrieved from Secrets Manager and every byte of query data. This is the exact "false-encryption" pattern documented for CDN-to-S3 origin (CTL.S3.CDN.TRANSPORT.001) and Cloudflare's Flexible mode: the client's TLS terminates at the edge service, the operator's mental model is "this is encrypted," and the actual confidentiality boundary is the path between the edge service and the origin. For Proxy-to-RDS, that path runs inside the VPC and is exposed to any same-VPC packet capture, ENI mirror, or compromised co-resident host. The fix is symmetric: require TLS at both hops; enforce certificate verification on the backend hop; reject any fallback that drops to plaintext.

**Remediation:** Set RequireTLS=true on the Proxy's target group; ensure the backend instance has TLS enforcement enabled.

---

### CTL.RDS.PUBLIC.001

**RDS Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.2; cis_aws_v3.0: 2.3.3; fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

RDS instances must not have public accessibility enabled. A publicly accessible database is reachable from the internet, exposing it to brute force attacks, SQL injection, and unauthorized data access.

**Remediation:** Modify the instance to disable public accessibility. Run: aws rds modify-db-instance --db-instance-identifier xxx --no-publicly-accessible --apply-immediately

---

### CTL.RDS.SECRET.EXISTS.001

**RDS Database Credentials Must Be Managed by Secrets Manager**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-5; pci_dss_v4: 8.2;

RDS instances must have their database credentials managed by AWS Secrets Manager — either via the native ManageMasterUserPassword integration (creates and rotates the secret automatically) or via a Secrets Manager secret tagged with the instance identifier. When credentials are NOT in Secrets Manager, they are stored somewhere — and that somewhere is invariably a worse place: application config files committed to git, ECS task definitions where the password appears in plaintext to anyone with task-definition- describe rights, Lambda environment variables visible in CloudFormation console output, SSM Parameter Store with String type (not encrypted at rest), or hardcoded into source. Each storage location is a separate exposure surface; every application that connects to the database has its own copy of the credential; rotation requires updating every copy in every consumer, which means rotation does not happen. Secrets Manager centralizes the credential, supports automatic rotation, and logs every retrieval via CloudTrail.

**Remediation:** Enable ManageMasterUserPassword on the instance, or create a Secrets Manager secret referenced by every application that connects.

---

### CTL.RDS.SG.BROAD.001

**RDS Security Group Must Not Allow Broad Ingress on Database Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

The RDS instance's associated security group must not allow 0.0.0.0/0 ingress on the database port. Broad ingress makes the database reachable from any IP address on the internet. Combined with PubliclyAccessible=true (CTL.RDS.PUBLIC.001), this creates direct internet exposure. Even with PubliclyAccessible=false, a broad SG allows access from anywhere within the VPC — defeating network segmentation if the VPC has a compromised instance.

**Remediation:** Replace the broad 0.0.0.0/0 rule with specific CIDR ranges (application server IPs, VPN exit IPs, or security group references for application-tier instances).

---

### CTL.RDS.SNAPSHOT.AWSKEY.SHARED.001

**Shared RDS Snapshots Must Be Encrypted with a Customer-Managed Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12;

RDS snapshots shared cross-account must be encrypted with a customer-managed KMS key (CMK) whose key policy grants the receiving account decrypt access — not the AWS-managed aws/rds key. The aws/rds key is account-specific: the receiving account cannot KMS:Decrypt against the source account's aws/rds key because the AWS-managed key policy does not permit cross-account use. The result is the particular failure mode where the snapshot share appears to succeed (the snapshot ARN shows up in the receiving account's `describe-db-snapshots --include-shared` results) but the actual restore fails the moment the receiving account calls `restore-db-instance-from-db-snapshot`, surfacing a KMS access-denied error that is hard to map back to "the source account encrypted with the wrong key." This is operational failure disguised as successful sharing, common in DR-rehearsal exercises and cross-account audit copy workflows. The fix is symmetric: snapshots intended to be shared cross-account are encrypted with a CMK whose key policy explicitly grants the receiving account decrypt rights.

**Remediation:** Copy the snapshot under a CMK with a cross-account-grant key policy and re-share the new snapshot.

---

### CTL.RDS.SNAPSHOT.CROSSENV.001

**Production RDS Snapshots Must Not Be Shared with Non-Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4: 9.4;

RDS snapshots whose source instance is tagged production (env=prod, tier=production, environment=prod, etc.) must not be shared with accounts tagged or known to be development, staging, or testing. Production database snapshots contain production data: customer records, transaction history, user authentication tables, API keys stored in config tables, PHI, PII, financial detail — every row the live database serves. Sharing the snapshot with a non-production account makes that data accessible to every developer who has database-restore rights in the receiving account, which is invariably a broader set of principals than the source account permits, operating under weaker network controls, less monitoring, and more permissive SCPs. Production data in a non-production environment escapes every production security control by construction. Same architectural pattern as CTL.EC2.EBS.CROSSENV.SNAPSHOT.001 applied to the database domain. The recommended path is synthetic or anonymized data for non-production workloads; sharing real snapshots is rarely required and almost always indicative of a shortcut taken under pressure.

**Remediation:** Revoke the share; supply synthetic or anonymized data to non-production environments instead.

---

### CTL.RDS.SNAPSHOT.ENCRYPT.001

**RDS Automated Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: RDS.4; hipaa: 164.312(a)(2)(iv); mitre_attack: TA0010; nist_800_53_r5: SC-28;

Unencrypted RDS snapshots can be copied to any AWS account and restored without requiring access to a KMS key. Snapshot encryption ensures that even if a snapshot is shared, it cannot be restored without the KMS key. RDS snapshot encryption follows the source instance's encryption setting — instances must be encrypted at creation.

**Remediation:** Create an encrypted copy of the snapshot, then restore a new instance from the encrypted snapshot. Migrate the application to the new encrypted instance.

---

### CTL.RDS.SNAPSHOT.EXPORT.001

**RDS Snapshot Export to S3 Must Be Restricted to Authorized Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1005; nist_800_53_r5: AC-3;

RDS snapshot export converts a database snapshot to Apache Parquet format and stores it in S3 — making the entire database contents accessible as files. An attacker with rds:StartExportTask permission can export any RDS snapshot to an attacker-controlled S3 bucket in any account. This is a complete database exfiltration primitive: no need to query row by row — export the snapshot and read all data as Parquet files.

**Remediation:** Restrict rds:StartExportTask via IAM policy to approved roles. Use a resource condition to limit S3 destination to approved buckets. Monitor for export tasks via CloudTrail alerting.

---

### CTL.RDS.SNAPSHOT.PUBLIC.001

**RDS Snapshots Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1537; nist_800_53_r5: AC-3;

RDS snapshots must not be publicly accessible. A public snapshot can be copied to any AWS account and restored as a full database, granting complete read access to all data.

**Remediation:** aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all

---

### CTL.RDS.SNAPSHOT.STALE.001

**Manual RDS Snapshots Must Not Persist Beyond the Retention Floor**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.310(d)(2)(i);

Manual RDS snapshots older than 365 days should be reviewed for deletion. Long-lived manual snapshots accumulate cost (snapshot storage is per-GB-per-month, charged indefinitely), and — more importantly — they accumulate data that becomes harder to govern over time. A 400-day-old snapshot may contain credentials that have since rotated, customer records that were marked for GDPR right-to-erasure deletion in the live database but never propagated to the historical snapshot, and audit rows from compliance windows that have since closed. Some retention policies require deletion after a period (not just retention up to a period — explicit deletion at GDPR-, HIPAA-, or contract-defined endpoints); long-lived snapshots violate the deletion side of that policy quietly. The control is low-severity because it is governance-focused, but the triage notes that retention and deletion are different obligations and a snapshot may satisfy retention while violating deletion.

**Remediation:** Delete the snapshot or document the retention requirement that mandates keeping it.

---

### CTL.RDS.SNAPSHOT.UNENCRYPTED.SHARED.001

**Shared RDS Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4: 3.4;

RDS snapshots that have been shared with another AWS account must be encrypted with a customer-managed KMS key whose key policy grants the receiving account decrypt access. An unencrypted shared snapshot gives the receiving account full plaintext access to the database: the receiving account restores the snapshot to a new RDS instance in their account, sets up their own master credentials, and reads every table, every row, every stored credential the source database held. There is no access control on the data itself — the source database's per-user grants do not carry across the restore. Encryption with a CMK provides the missing control plane: the receiving account can read only as long as the source account leaves the CMK enabled and the key policy in place, revocation is immediate via key disable or policy change, and every cross-account decrypt is logged in CloudTrail. Distinct from CTL.RDS.SNAPSHOT.PUBLIC.001 (which catches snapshots shared with `all`) — this control catches the "shared with named accounts but unencrypted" case.

**Remediation:** Re-share an encrypted (CMK) copy of the snapshot and revoke the unencrypted share.

---

### CTL.RDS.SSL.001

**RDS Must Require SSL Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 2.3.3; fedramp_moderate: SC-8; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

RDS instances must enforce SSL/TLS for all client connections. Without require_ssl, database traffic travels unencrypted over the network, exposing query data and credentials to interception.

**Remediation:** Set the rds.force_ssl parameter to 1 in the parameter group (PostgreSQL) or require_secure_transport to ON (MySQL). For Aurora, use the cluster parameter group.

---

### CTL.RDS.SSL.ENFORCE.001

**RDS Instances Must Enforce SSL/TLS for All Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: RDS.25; hipaa: 164.312(e)(2)(ii); mitre_attack: TA0006; nist_800_53_r5: SC-8;

RDS connections without SSL/TLS transmit database credentials and query results in plaintext over the network. In a VPC, any compromised instance with network access can capture database passwords and sensitive data via passive network monitoring. SSL enforcement is configured via parameter group (require_secure_transport for MySQL, rds.force_ssl for PostgreSQL/SQL Server).

**Remediation:** Set the appropriate SSL parameter in the parameter group: MySQL: require_secure_transport=ON. PostgreSQL: rds.force_ssl=1. SQL Server: rds.force_ssl=1.

---

### CTL.RDS.TLS.CACERT.001

**RDS Instances Must Use a Current CA Certificate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4: 4.1;

RDS instances must use the current AWS-issued CA certificate bundle (rds-ca-rsa2048-g1 or rds-ca-rsa4096-g1 family) and not the deprecated rds-ca-2019 bundle. AWS rotates the RDS server certificate authority on a published schedule; applications that verify the server certificate (the recommended posture for any production database client) must trust the CA the instance presents. When the instance is still pinned to an older CA, three failure modes follow on the published expiry: production clients that verify the certificate begin failing connection with an "untrusted issuer" error all at once, instances that the team forgot to migrate become unreachable until they are rotated, and emergency rotation under outage pressure tends to be done with verify_ca disabled, which silently downgrades the security posture for every connection thereafter. The control fires preemptively so the rotation is paid in change-window time, not in incident time.

**Remediation:** Modify the instance to use the current CA bundle and verify clients trust it.

---

### CTL.RDS.TLS.VERSION.001

**RDS Instances Must Not Accept Deprecated TLS Versions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-13; pci_dss_v4: 4.1;

RDS instances must reject TLS 1.0 and TLS 1.1 connections and require TLS 1.2 or higher. TLS 1.0 carries the BEAST and POODLE weaknesses (publicly exploited as long ago as 2011 and 2014 respectively); TLS 1.1 lacks the modern cipher suites and AEAD modes that downstream cryptographic guidance now assumes. Both are deprecated by RFC 8996 and removed from PCI-DSS-acceptable configurations as of v3.2.1. When the parameter group permits these versions, a client that downgrades — by attacker manipulation or by being a legacy library that never advanced past TLS 1.0 — connects successfully and the encryption applied is below the level the rest of the security review assumed.

**Remediation:** Update the parameter group to require TLS 1.2 minimum.

---


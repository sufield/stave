# Control Reference — EFS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EFS.AP.POSIX.001

**EFS Access Points Must Enforce POSIX Identity**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

EFS access points without a POSIX user identity allow clients to connect with any UID/GID, enabling privilege escalation across tenants sharing the file system. Every access point must enforce a fixed POSIX user to constrain file ownership and permissions.

**Remediation:** Update the access point to enforce a POSIX user. Run: aws efs create-access-point --file-system-id fs-xxx --posix-user Uid=1000,Gid=1000

---

### CTL.EFS.AP.ROOT.001

**EFS Access Points Must Not Expose Root Directory**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

EFS access points with a root directory grant clients visibility into the entire file system tree. Each access point should scope access to a specific subdirectory to enforce least-privilege and prevent data exfiltration across application boundaries.

**Remediation:** Recreate the access point with a scoped root directory path. Run: aws efs create-access-point --file-system-id fs-xxx --root-directory Path=/app/data,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=755}

---

### CTL.EFS.BACKUP.001

**EFS File System Must Have Backup Policy Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7)(ii)(A); nist_800_53_r5: CP-9;

EFS file systems must have automatic backups enabled via AWS Backup. Without a backup policy, data loss from accidental deletion, ransomware, or corruption cannot be recovered, violating disaster recovery and business continuity requirements.

**Remediation:** Enable automatic backups for the EFS file system. Run: aws efs put-backup-policy --file-system-id fs-xxx --backup-policy Status=ENABLED

---

### CTL.EFS.ENCRYPT.001

**EFS File System Must Be Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

EFS file systems must have encryption at rest enabled. Data stored on unencrypted file systems is readable if the underlying storage is compromised. EFS encryption uses AWS KMS and must be enabled at creation time — it cannot be enabled on existing file systems.

**Remediation:** Create a new encrypted EFS file system and migrate data. Encryption cannot be enabled on existing file systems. Run: aws efs create-file-system --encrypted --kms-key-id alias/aws/elasticfilesystem

---

### CTL.EFS.ENCRYPT.TRANSIT.001

**EFS File System Must Enforce Encryption in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.4.1; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.1;

EFS file systems must enforce encryption in transit via a file system policy that denies unencrypted connections. Without this policy, NFS clients can mount the file system without TLS, exposing data to network-level interception.

**Remediation:** Apply a file system policy that denies unencrypted transport. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'

---

### CTL.EFS.INCOMPLETE.001

**Complete Data Required for EFS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

EFS file system safety cannot be assessed when encryption status is missing from the snapshot. The extractor must populate filesystem.encryption.at_rest_enabled.

**Remediation:** Re-run the extractor with EFS permissions: elasticfilesystem:DescribeFileSystems, elasticfilesystem:DescribeFileSystemPolicy.

---

### CTL.EFS.KMS.CMK.001

**EFS File System Must Use Customer-Managed KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.6.1;

EFS file systems encrypted with the AWS-managed key (aws/elasticfilesystem) cannot enforce key policies, rotation schedules, or cross-account access restrictions. A customer-managed KMS key is required for full control over the encryption lifecycle and to meet compliance frameworks that mandate key management separation.

**Remediation:** Create a new EFS file system with a customer-managed KMS key and migrate data. The KMS key type cannot be changed after creation. Run: aws efs create-file-system --encrypted --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY-ID

---

### CTL.EFS.LIFECYCLE.001

**EFS File System Should Have Lifecycle Policy Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9;

EFS file systems should have a lifecycle policy that transitions infrequently accessed files to the Infrequent Access (IA) storage class. Without a lifecycle policy, all files remain in the Standard storage class regardless of access patterns, increasing storage costs and reducing operational resilience through budget inefficiency.

**Remediation:** Configure a lifecycle policy to transition infrequently accessed files. Run: aws efs put-lifecycle-configuration --file-system-id fs-xxx --lifecycle-policies TransitionToIA=AFTER_30_DAYS

---

### CTL.EFS.MT.SG.001

**EFS Mount Targets Must Have Security Groups Attached**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7;

EFS mount targets must have security groups attached to control network access. Mount targets without security groups accept connections from any source within the VPC, enabling unauthorized NFS access from compromised workloads.

**Remediation:** Attach a security group to the mount target that restricts NFS (port 2049) to authorized sources. Run: aws efs modify-mount-target-security-groups --mount-target-id fsmt-xxx --security-groups sg-xxx

---

### CTL.EFS.MULTIAZ.001

**EFS File System Must Use Multi-AZ Deployment**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EFS file systems must be Regional type (not One Zone) with mount targets in multiple Availability Zones. Single-AZ concentration means an AZ outage severs all client connectivity.

**Remediation:** Use Regional storage class and create mount targets in multiple AZs.

---

### CTL.EFS.POLICY.ANONYMOUS.001

**EFS File System Policy Must Prevent Anonymous Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3;

EFS file system policies must prevent anonymous (unauthenticated) access. Without this policy, any principal that can reach the mount target can access the file system without IAM authentication, enabling unauthorized data access from within the VPC.

**Remediation:** Apply a file system policy that prevents anonymous access. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"elasticfilesystem:AccessedViaMountTarget":"true"}}, "Resource":"*"}]}'

---

### CTL.EFS.POLICY.DENYROOT.001

**EFS File System Policy Must Deny Root Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6;

EFS file system policies must include a statement denying root access. Without this policy, NFS clients mounting the file system can operate as root (UID 0), bypassing POSIX permission boundaries and enabling full read/write access to all files.

**Remediation:** Apply a file system policy that denies root access. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"elasticfilesystem:ClientRootAccess","Resource":"*"}]}'

---

### CTL.EFS.POLICY.TRANSIT.001

**EFS File System Policy Must Enforce In-Transit Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-8;

EFS file system policies must enforce encryption in transit by denying connections that do not use TLS. Without this policy, NFS clients can mount the file system over plaintext, exposing data to network-level interception and credential sniffing.

**Remediation:** Apply a file system policy that enforces in-transit encryption. Run: aws efs put-file-system-policy --file-system-id fs-xxx --policy '{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}, "Action":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}, "Resource":"*"}]}'

---


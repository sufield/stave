# Control Reference — FSX

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.FSX.BACKUP.CONFIGURED.001

**FSx File System Must Have Backups Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; pci_dss_v4.0: 3.4; soc2: A1.2;

FSx file system does not have automatic backups or AWS Backup configured. Without backups, ransomware encryption or accidental deletion of the file system results in permanent data loss. FSx supports automatic daily backups with configurable retention and AWS Backup integration.

**Remediation:** Enable automatic backups on the FSx file system with a retention period appropriate to the data's recovery requirements, or configure AWS Backup to include the file system in a backup plan.

---

### CTL.FSX.ENCRYPT.REST.001

**FSx File System Must Have At-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Amazon FSx file systems must have at-rest encryption enabled. FSx stores customer data — file shares, home directories, application data — on persistent storage volumes. Without encryption at rest, data on the underlying disks is readable by anyone with physical or snapshot access. FSx for Lustre, Windows File Server, NetApp ONTAP, and OpenZFS all support encryption at rest using AWS KMS keys, but it must be enabled at creation time and cannot be changed afterward.

**Remediation:** Create a new FSx file system with encryption at rest enabled (cannot be changed on existing file systems). Migrate data from the unencrypted file system to the new encrypted one using AWS DataSync or native file copy.

---


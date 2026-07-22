# Control Reference — ACCOUNT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

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


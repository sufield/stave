# Control Reference — ACCOUNT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACCOUNT.ENCRYPT.DEFAULT.PARITY.001

**Account Encryption Defaults Must Be Enabled Consistently**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Account-level default encryption is enabled for some storage services but not all. EBS default encryption may be on (CTL.EC2.EBS.DEFAULT.001) while RDS and EFS storage created in the same account is not encrypted by default. This is a PART OF gap: the account enforces encryption-at-rest defaults for one storage type but not others, so new resources created in unprotected services are unencrypted unless the creator explicitly enables encryption. The fix is to enable default encryption for all storage services at the account level so no new resource can be created without encryption.

**Remediation:** Enable default encryption for all storage services: - EBS: aws ec2 enable-ebs-encryption-by-default - RDS: aws rds modify-certificates (ensure new instances default to encryption) - EFS: enforce encryption via SCP or IaC policy Verify with aws ec2 get-ebs-encryption-by-default for EBS.

---


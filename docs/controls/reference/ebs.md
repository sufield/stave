# Control Reference — EBS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EBS.AMI.DEREGPROTECTION.001

**AMI Deregistration Protection Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9, SI-7; soc2: CC6.1;

AMI does not have deregistration protection enabled. Without deregistration protection, an attacker with ec2:DeregisterImage can remove the AMI, preventing new launches from the golden image and forcing fallback to potentially compromised or outdated alternatives. Deregistration protection is especially critical for AMIs used in Auto Scaling groups and launch templates where the AMI ID is a hard dependency.

**Remediation:** Enable deregistration protection on the AMI using ec2:EnableImageDeregistrationProtection. Combine with SCP restrictions on ec2:DisableImageDeregistrationProtection to prevent attackers from removing the protection.

---

### CTL.EBS.SNAPSHOT.DELETEPROTECTION.001

**EBS Snapshot Lock Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9, SC-28; soc2: CC6.1;

EBS snapshot does not have snapshot lock enabled. Snapshot lock prevents deletion for a configurable retention period, providing protection against both accidental and malicious deletion. Combined with Recycle Bin, snapshot lock is the primary defense against ransomware that targets backup artifacts. Without it, an attacker with ec2:DeleteSnapshot can permanently destroy recovery points.

**Remediation:** Enable snapshot lock on critical snapshots using ec2:LockSnapshot. Set the lock mode to compliance for immutable protection or governance for removable protection. Set a retention period that exceeds your recovery time objective.

---


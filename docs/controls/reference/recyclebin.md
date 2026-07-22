# Control Reference — RECYCLEBIN

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.RECYCLEBIN.EBS.RETENTION.001

**Recycle Bin Retention Period Below Minimum**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9, CP-10; soc2: CC6.1;

Recycle Bin retention rule for EBS resources has a retention period below the recommended minimum (7 days). Short retention periods give insufficient time to detect and recover from ransomware or accidental deletion. A 1-day retention period means a Friday deletion is unrecoverable by Monday morning. The retention period should exceed the organization's mean time to detect (MTTD) for data destruction events.

**Remediation:** Update the Recycle Bin retention rule to at least 7 days. For production workloads, consider 30 days to ensure detection and recovery time for sophisticated attacks.

---

### CTL.RECYCLEBIN.EBS.VOLUME.001

**Recycle Bin Rule Exists for EBS Volumes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC6.1;

A Recycle Bin retention rule must exist for EBS volumes. Previously Recycle Bin only supported snapshots; it now supports EBS volumes directly. Without a retention rule, deleted EBS volumes are immediately and irrecoverably destroyed. Recycle Bin is not enabled by default — it must be explicitly configured. Combined with SCP protection (CTL.ORG.SCP.PROTECTRECYCLEBIN.001), this ensures deleted volumes are recoverable and the recovery mechanism itself cannot be disabled by an attacker.

**Remediation:** Create a Recycle Bin retention rule with resource type ebs:volume. Set the retention period to at least 7 days. Protect the rule from deletion with an SCP denying rbin:DeleteRule and rbin:UpdateRule.

---


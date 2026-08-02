# Control Reference — DATASYNC

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DATASYNC.EXTERNAL.DESTINATION.001

**DataSync Tasks Must Not Target External Destinations**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No DataSync task should target a location outside the organization. DataSync can move terabytes per hour — it is the fastest exfiltration path in AWS. An attacker with datasync:CreateTask can configure a task to copy S3/EFS/FSx data to an external location. Linked to Muddled Libra campaigns (2024) documented by Wiz. Technique: Wiz "Exfiltration via AWS DataSync".

**Remediation:** Verify the destination is legitimate. If not, delete the task immediately. Add an SCP denying datasync:CreateTask or restricting destination locations via conditions.

---

### CTL.DATASYNC.ROLE.OVERBROAD.001

**DataSync Task Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

DataSync task's IAM role has permissions beyond what the data transfer requires. DataSync tasks need access to the specific source and destination locations (S3 buckets, EFS filesystems, FSx shares, or NFS/SMB endpoints) and CloudWatch Logs for task logging. Any action outside this set — s3:*, efs:*, iam:PassRole — means the DataSync agent can access storage beyond its transfer scope.

**Remediation:** Scope the DataSync role to the specific source and destination location ARNs. Use separate roles for tasks with different source-destination pairs. Remove wildcard storage actions.

---


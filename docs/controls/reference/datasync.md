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


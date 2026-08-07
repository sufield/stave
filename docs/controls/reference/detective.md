# Control Reference — DETECTIVE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DETECTIVE.DELIVERY.HEALTH.001

**Detective Graph Must Be Actively Ingesting Data**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-4; nist_800_53_r5: IR-4; soc2: CC7.3;

Detective behavior graph must be actively ingesting data from its configured sources. Detective can be enabled with member accounts invited and pass initial setup checks while the graph's underlying data ingestion silently stops. When ingestion fails, the behavior graph becomes stale — investigation queries return outdated entity profiles, IP address lookups miss recent activity, and finding group enrichment lacks current context. The Detective console shows the graph as "Enabled" and historical data remains queryable, but no new GuardDuty findings, CloudTrail events, or VPC flow logs are being ingested for analysis. This is the detection delivery pattern applied to the investigation service: the tool appears ready but its data foundation has eroded.

**Remediation:** Check Detective graph data source status and volume metrics. Common causes: GuardDuty detector disabled or suspended in a member account, VPC flow log delivery to Detective interrupted, CloudTrail management events not available in the region, or member account disassociated from the graph. Verify data source ingestion by checking the volume statistics in the Detective console — zero volume for any source indicates a break.

---

### CTL.DETECTIVE.ENABLED.001

**Amazon Detective Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, SI-4; soc2: CC7.2;

Amazon Detective is not enabled. Detective aggregates and analyzes findings from GuardDuty, Security Hub, and VPC Flow Logs to help investigate security incidents. Without Detective, incident investigation relies on manual log correlation.

**Remediation:** Enable Amazon Detective in the account to provide automated investigation capabilities for security findings.

---


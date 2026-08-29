# Control Reference — KINESIS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.KINESIS.ENCRYPT.001

**Kinesis Streams Must Be Encrypted At Rest with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Kinesis Data Streams must use server-side encryption with KMS to protect records at rest. Streams without KMS encryption store records in plaintext — readable by anyone with stream read permissions.

**Remediation:** Enable server-side encryption on the stream with a KMS key via aws kinesis start-stream-encryption.

---

### CTL.KINESIS.ENCRYPT.CMK.001

**Kinesis Stream Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Kinesis Data Streams with server-side encryption must use a customer-managed KMS key, not the AWS-managed `aws/kinesis` default. The AWS-managed key has a key policy the customer cannot edit and cannot be revoked or rotated on the customer's schedule. Customer-managed keys provide per-tenant key-policy control and per-incident key-revocation capability.

**Remediation:** Update the stream encryption to use a customer-managed KMS key via aws kinesis start-stream-encryption --encryption-type KMS --key-id arn:aws:kms:...

---

### CTL.KINESIS.LOG.MONITORING.001

**Kinesis Data Stream Must Have Enhanced Monitoring Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

Kinesis data stream does not have enhanced monitoring enabled. Enhanced monitoring provides per-shard metrics that expose throttling, iterator age, and read/write throughput anomalies not visible in basic monitoring. Without it, data exfiltration via high-volume reads or stream poisoning via injected records may go undetected.

**Remediation:** Enable enhanced (shard-level) monitoring for the Kinesis data stream to gain per-shard visibility into throughput and latency metrics.

---

### CTL.KINESIS.MODE.PROVISIONED.001

**Kinesis Stream Should Use On-Demand Capacity Mode**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** config
- **Compliance:** nist_800_53_r5: SA-8;

Kinesis data streams using provisioned capacity mode should migrate to on-demand mode. Provisioned mode is the legacy capacity model that requires manual shard management and capacity planning. On-demand mode automatically scales throughput and eliminates the operational burden of shard splitting and merging. Some high-throughput workloads may legitimately use provisioned mode for cost optimization at scale — this finding is informational for those cases.

**Remediation:** Switch the stream to on-demand mode. Use aws kinesis update-stream-mode --stream-arn <arn> --stream-mode-details StreamMode=ON_DEMAND. On-demand mode automatically scales throughput up to the account limits. Review cost implications — on-demand pricing differs from provisioned shard-hour pricing.

---

### CTL.KINESIS.MONITORING.001

**Kinesis Streams Must Have Enhanced Shard-Level Monitoring Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

Kinesis Data Streams must have enhanced shard-level monitoring enabled. Without it, only stream-level CloudWatch metrics are available — aggregated across all shards. Shard-level metrics (IncomingBytes, IncomingRecords, ReadProvisionedThroughputExceeded, WriteProvisionedThroughputExceeded, IteratorAgeMilliseconds per shard) are required to detect hot shards, consumer lag on individual shards, and anomalous write patterns that indicate data exfiltration or injection. A bulk data extraction targeting a single shard is invisible at the stream level if other shards are idle. Enhanced monitoring adds per-shard metrics to CloudWatch at one-minute granularity, enabling shard-level alarms and forensic analysis.

**Remediation:** Enable enhanced monitoring on the stream: aws kinesis enable-enhanced-monitoring --stream-name <name> --shard-level-metrics ALL. Review per-shard metrics in CloudWatch to identify hot shards and configure alarms on ReadProvisionedThroughputExceeded and IteratorAgeMilliseconds per shard.

---

### CTL.KINESIS.POLICY.CROSSACCOUNT.001

**Kinesis Stream Resource Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6;

Kinesis Data Streams resource policy grants actions to principals in external AWS accounts without an aws:PrincipalOrgID condition. External accounts can GetRecords (exfiltrate stream data) or PutRecord (inject data into the stream pipeline). If the account leaves the organization, access persists. Same shape as CTL.SNS.POLICY.CROSSACCOUNT.001 on the streaming side.

**Remediation:** Add aws:PrincipalOrgID restricting access to the organization's ID. For a legitimate cross-org consumer, use aws:PrincipalAccount with the explicit account ID and document the trust relationship.

---

### CTL.KINESIS.RETENTION.001

**Kinesis Streams Must Meet Minimum Data Retention Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-11; soc2: A1.1;

Kinesis Data Streams must retain records for at least the required minimum duration (default 168 hours / 7 days). Short retention windows reduce forensic capability and prevent replay of missed events by downstream consumers.

**Remediation:** Increase the stream retention period via aws kinesis increase-stream-retention-period.

---


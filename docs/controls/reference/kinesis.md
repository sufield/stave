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

### CTL.KINESIS.RETENTION.001

**Kinesis Streams Must Meet Minimum Data Retention Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-11; soc2: A1.1;

Kinesis Data Streams must retain records for at least the required minimum duration (default 168 hours / 7 days). Short retention windows reduce forensic capability and prevent replay of missed events by downstream consumers.

**Remediation:** Increase the stream retention period via aws kinesis increase-stream-retention-period.

---


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

### CTL.KINESIS.RETENTION.001

**Kinesis Streams Must Meet Minimum Data Retention Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-11; soc2: A1.1;

Kinesis Data Streams must retain records for at least the required minimum duration (default 168 hours / 7 days). Short retention windows reduce forensic capability and prevent replay of missed events by downstream consumers.

**Remediation:** Increase the stream retention period via aws kinesis increase-stream-retention-period.

---


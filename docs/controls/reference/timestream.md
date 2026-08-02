# Control Reference — TIMESTREAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TIMESTREAM.ENCRYPT.CMK.001

**Timestream Database Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Timestream databases must encrypt at rest with a customer-managed KMS key, not the AWS-owned default. Timestream encrypts all data by default using an AWS-owned key. Time-series data often includes IoT telemetry, application metrics, and operational data that may contain sensitive workload identifiers or behavioral patterns. The AWS-owned key cannot be audited, scoped, or revoked per tenant.

**Remediation:** Update the database KMS key using aws timestream-write update-database --kms-key-id with a customer-managed key ARN. Timestream supports in-place key changes.

---


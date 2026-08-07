# Control Reference — FIREHOSE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.FIREHOSE.ENCRYPT.REST.001

**Kinesis Data Firehose Delivery Stream Must Enable Server-Side Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Kinesis Data Firehose delivery streams must have server-side encryption enabled. Firehose buffers incoming records before delivering them to S3, Redshift, OpenSearch, or HTTP endpoints. Without SSE the buffer contents — which may include log events, clickstream data, or application telemetry containing PII — are stored unencrypted in the Firehose service's internal storage during the buffering interval.

**Remediation:** Enable SSE on the delivery stream using aws firehose start-delivery-stream-encryption with a customer-managed KMS key. SSE can be enabled on existing streams without recreation.

---

### CTL.FIREHOSE.GHOST.S3.001

**Firehose Delivery Stream S3 Destination Bucket Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2, SC-8; hipaa: 164.312(b), 164.312(e)(1); iso_27001_2022: A.5.16, A.8.15, A.8.24; nist_800_53_r5: AU-2, AU-9, SC-8, SI-4; pci_dss_v4.0: 10.1, 10.5; soc2: CC6.1, CC7.1, CC8.1;

Amazon Data Firehose delivery stream is configured to deliver records to an S3 bucket that has been deleted. Firehose buffers records and attempts delivery, but every delivery attempt fails. If the bucket name is re-registered under a different account, Firehose may resume delivery to attacker-controlled storage — the bucket hijacking vector documented by Unit 42. The delivery stream configuration appears valid; the destination ARN shows the bucket name; the bucket no longer exists or has been re-registered.

**Remediation:** Recreate the S3 bucket with the original name and restore the bucket policy granting firehose.amazonaws.com PutObject access, or update the delivery stream destination: aws firehose update-destination --delivery-stream-name <name> --current-delivery-stream-version-id <ver> --extended-s3-destination-update BucketARN=arn:aws:s3:::<new-bucket>,RoleARN=<role>. Investigate whether the bucket was re-registered under a different account during the gap period.

---

### CTL.FIREHOSE.LOG.ERROR.001

**Firehose Delivery Stream Must Have Error Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

Firehose delivery stream does not have error logging enabled. Error logging captures delivery failures, transformation errors, and format conversion issues to CloudWatch. Without it, data loss from failed deliveries and potential data exfiltration via delivery redirection go undetected.

**Remediation:** Enable CloudWatch error logging for the Firehose delivery stream to capture delivery failures and transformation errors.

---

### CTL.FIREHOSE.ROLE.OVERBROAD.001

**Firehose Delivery Stream Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Kinesis Data Firehose delivery stream's IAM role has permissions beyond what the delivery pipeline requires. Firehose streams need write access to the specific destination (a single S3 bucket, Redshift cluster, OpenSearch domain, or HTTP endpoint), optional KMS encrypt permissions for the destination key, and CloudWatch Logs for delivery error logging. Any action outside this set — s3:*, redshift:*, opensearch:* on broad targets — means a compromised or misconfigured delivery stream role can write to storage beyond its pipeline scope or read data it should not access.

**Remediation:** Scope the delivery role to the specific destination resource: the target S3 bucket ARN, the specific Redshift cluster, or the OpenSearch domain. Remove wildcard storage actions. Each delivery stream should have its own role scoped to its single destination.

---


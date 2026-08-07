# Control Reference — DAX

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DAX.AUTH.REQUIRED.001

**DAX Cluster Must Require Authentication**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

DynamoDB Accelerator (DAX) cluster does not require IAM authentication. Without authentication, any application with network access to the cluster endpoint can read and write cached data without credentials.

**Remediation:** Enable IAM authentication for the DAX cluster.

---

### CTL.DAX.LOG.CLOUDWATCH.001

**DAX CloudWatch Logging Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

DynamoDB Accelerator (DAX) cluster does not have CloudWatch logging enabled. Without logging, cache operations are not recorded, limiting visibility into access patterns and potential data exfiltration via the cache layer.

**Remediation:** Enable CloudWatch logging for the DAX cluster.

---

### CTL.DAX.SECRET.PLAIN.001

**DAX Cluster Credentials Must Use Secrets Manager**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

DAX cluster credentials are not managed through AWS Secrets Manager. Hardcoded cluster credentials risk exposure and complicate rotation.

**Remediation:** Store DAX cluster credentials in AWS Secrets Manager and configure automatic rotation.

---


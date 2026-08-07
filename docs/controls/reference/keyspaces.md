# Control Reference — KEYSPACES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.KEYSPACES.AUTH.REQUIRED.001

**Keyspaces Table Must Require Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

Amazon Keyspaces (Cassandra-compatible) endpoint does not require IAM or SigV4 authentication. Keyspaces supports both SigV4 (IAM-based) and service-specific credentials. Without authentication enforcement, any client with network access to the CQL endpoint can read and write table data.

**Remediation:** Configure Keyspaces to require SigV4 (IAM) authentication for all CQL connections. Avoid service-specific credentials where IAM authentication is available.

---

### CTL.KEYSPACES.ENCRYPT.CMK.001

**Amazon Keyspaces Table Must Use Customer-Managed Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Amazon Keyspaces tables must use a customer-managed KMS key for encryption at rest instead of the AWS-owned key. Keyspaces encrypts all tables by default using an AWS-owned key, but the AWS-owned key has no customer-visible key policy, cannot be audited via CloudTrail KMS events, and cannot be revoked per tenant. Using a customer-managed key provides key-policy scoping, CloudTrail visibility into every decrypt call, and the ability to revoke access by disabling the key.

**Remediation:** Alter the table to use a customer-managed KMS key: ALTER TABLE keyspace.table WITH custom_properties = {'encryption_specification': {'encryption_type': 'CUSTOMER_MANAGED_KMS_KEY', 'kms_key_identifier': 'arn:aws:kms:...'}}.

---

### CTL.KEYSPACES.LOG.AUDIT.001

**Keyspaces Audit Logging Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

Amazon Keyspaces table does not have audit logging enabled. Without audit logging, CQL operations against the keyspace are not recorded, limiting forensic capability after a data breach or unauthorized access event.

**Remediation:** Enable audit logging for the Keyspaces keyspace to record CQL operations in CloudWatch Logs.

---

### CTL.KEYSPACES.PITR.ENABLED.001

**Keyspaces Table Must Have Point-in-Time Recovery Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

Amazon Keyspaces table does not have point-in-time recovery enabled. Without PITR, accidental deletes or application bugs that corrupt table data cannot be recovered.

**Remediation:** Enable point-in-time recovery for the Keyspaces table.

---

### CTL.KEYSPACES.SECRET.PLAIN.001

**Keyspaces Connection Credentials Must Use Secrets Manager**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Keyspaces connection credentials are not managed through AWS Secrets Manager. Hardcoded CQL credentials risk exposure and complicate rotation.

**Remediation:** Store Keyspaces CQL credentials in AWS Secrets Manager and configure automatic rotation.

---


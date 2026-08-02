# Control Reference — KEYSPACES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.KEYSPACES.ENCRYPT.REST.001

**Amazon Keyspaces Table Must Use Customer-Managed Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Amazon Keyspaces tables must use a customer-managed KMS key for encryption at rest instead of the AWS-owned key. Keyspaces encrypts all tables by default using an AWS-owned key, but the AWS-owned key has no customer-visible key policy, cannot be audited via CloudTrail KMS events, and cannot be revoked per tenant. Using a customer-managed key provides key-policy scoping, CloudTrail visibility into every decrypt call, and the ability to revoke access by disabling the key.

**Remediation:** Alter the table to use a customer-managed KMS key: ALTER TABLE keyspace.table WITH custom_properties = {'encryption_specification': {'encryption_type': 'CUSTOMER_MANAGED_KMS_KEY', 'kms_key_identifier': 'arn:aws:kms:...'}}.

---


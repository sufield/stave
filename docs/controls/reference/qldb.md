# Control Reference — QLDB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.QLDB.ENCRYPT.CMK.001

**QLDB Ledger Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

QLDB ledgers must encrypt at rest with a customer-managed KMS key, not the AWS-owned default. QLDB encrypts all data by default using an AWS-owned key that the customer cannot audit, scope, or revoke. A ledger stores immutable financial and regulatory records — the inability to revoke the encryption key per tenant or audit decrypt operations via CloudTrail is a compliance gap for any regulated workload.

**Remediation:** Update the ledger's KMS key using aws qldb update-ledger --kms-key-arn with a customer-managed key ARN. QLDB supports in-place key rotation without ledger recreation.

---


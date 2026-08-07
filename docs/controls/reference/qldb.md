# Control Reference — QLDB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.QLDB.AUTH.SESSION.001

**QLDB Ledger Must Require Session Authentication**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

Amazon QLDB ledger does not require session authentication. Without session-level authentication, any principal with network access can open a QLDB session and execute PartiQL queries against the ledger.

**Remediation:** Configure the QLDB ledger to require IAM session authentication.

---

### CTL.QLDB.ENCRYPT.CMK.001

**QLDB Ledger Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

QLDB ledgers must encrypt at rest with a customer-managed KMS key, not the AWS-owned default. QLDB encrypts all data by default using an AWS-owned key that the customer cannot audit, scope, or revoke. A ledger stores immutable financial and regulatory records — the inability to revoke the encryption key per tenant or audit decrypt operations via CloudTrail is a compliance gap for any regulated workload.

**Remediation:** Update the ledger's KMS key using aws qldb update-ledger --kms-key-arn with a customer-managed key ARN. QLDB supports in-place key rotation without ledger recreation.

---

### CTL.QLDB.EXPORT.CONFIGURED.001

**QLDB Ledger Must Have Export Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

QLDB ledger does not have journal export configured. QLDB is being deprecated — data should be exported to S3 for long-term retention and migration to alternative services.

**Remediation:** Configure journal export to S3 for the QLDB ledger.

---


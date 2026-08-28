# Control Reference — AUDITMANAGER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AUDITMANAGER.ENABLED.001

**AWS Audit Manager Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CA-7; scs_c02: 8.11; soc2: CC4.1;

AWS Audit Manager is not enabled. Without Audit Manager, compliance evidence collection is manual, assessments are not automated, and there is no centralized framework for mapping controls to compliance standards.

**Remediation:** Enable Audit Manager and configure a default assessment reports destination: aws auditmanager register-account.

---

### CTL.AUDITMANAGER.ENCRYPT.CMK.001

**Audit Manager Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Audit Manager account settings do not specify a customer-managed KMS key. Audit Manager stores assessment evidence, control evaluations, and compliance reports. Without a customer-managed key, all assessment data uses AWS-managed encryption with no customer-controlled key policy or usage audit trail.

**Remediation:** Update Audit Manager settings with a customer-managed KMS key via UpdateSettings. The kmsKey field accepts a KMS key ARN.

---


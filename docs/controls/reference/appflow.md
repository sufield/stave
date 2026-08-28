# Control Reference — APPFLOW

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPFLOW.FLOW.ENCRYPT.CMK.001

**AppFlow Flow Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

AppFlow flow does not use a customer-managed KMS key. Flows transfer data between SaaS applications and AWS services, processing potentially sensitive business data (CRM records, financial transactions, HR data). Without a customer-managed key, the flow's kmsArn defaults to AWS-managed encryption. Connector profiles have no KMS field — encryption is flow-level.

**Remediation:** Update the flow with a customer-managed KMS key via UpdateFlow, setting the kmsArn parameter.

---


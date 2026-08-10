# Control Reference — COMPREHEND

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.COMPREHEND.SHADOW.ENDPOINT.001

**Comprehend Endpoint in Account Not Designated for AI Workloads**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, AC-3; soc2: CC6.1;

A Comprehend endpoint is deployed in an account not designated for AI workloads. Comprehend processes natural language text for sentiment, entities, and PII detection. In an unsanctioned account, Comprehend endpoints can process sensitive documents without data classification controls.

**Remediation:** Delete the endpoint or authorize the account for AI workloads after security review.

---


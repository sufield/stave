# Control Reference — TEXTRACT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TEXTRACT.SHADOW.USAGE.001

**Textract Usage in Account Not Designated for AI Workloads**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-7, AC-3; soc2: CC6.1;

Textract usage detected in an account not designated for AI workloads. Textract extracts text and structured data from scanned documents. In an unsanctioned account, Textract can process sensitive documents (contracts, financial records, medical forms) without data classification or DLP controls.

**Remediation:** Restrict Textract API access via IAM policies or authorize the account for AI workloads after security review.

---


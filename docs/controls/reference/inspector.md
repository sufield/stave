# Control Reference — INSPECTOR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.INSPECTOR.ENABLED.001

**Amazon Inspector Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: RA-5; soc2: CC7.1;

Amazon Inspector 2 must be enabled for vulnerability scanning of EC2, ECR, and Lambda resources. Without Inspector, known vulnerabilities in deployed software go undetected.

**Remediation:** Enable Inspector 2 for EC2, ECR, and Lambda scanning.

---


# Control Reference — APPRUNNER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPRUNNER.SERVICE.ACTIVE.001

**App Runner Services Are Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active App Runner services. App Runner provisions fully managed container compute with public HTTPS endpoints in an AWS-managed VPC outside the customer's governance boundary. Services are not visible through ec2:DescribeInstances or standard network security monitoring and run with IAM execution roles that may have broad permissions.

**Remediation:** Evaluate intent; if unwanted, delete services and SCP deny apprunner:*.

---


# Control Reference — CFN

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CFN.PARAM.NOECHO.001

**CloudFormation Parameters for Sensitive Values Must Have NoEcho Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

CloudFormation template parameters that are likely to contain sensitive values must have NoEcho set to true. Without NoEcho, parameter values are visible in stack events, stack details, and change set descriptions. Any IAM principal with cloudformation:DescribeStacks can read them in plaintext. This control checks the NoEcho property — not the parameter value or default.

**Remediation:** Add NoEcho: true to the parameter definition in the CloudFormation template. Redeploy the stack. Note that existing stack events may still contain the plaintext value — rotate the credential after enabling NoEcho.

---


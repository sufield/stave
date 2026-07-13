# Control Reference — CLOUD9

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CLOUD9.ENV.ACTIVE.001

**Cloud9 Environments Are Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active Cloud9 environments. Cloud9 creates EC2 instances with security groups and IAM credential access behind the Cloud9 API surface. Environments can have direct SSH access from the internet and inherit the creating principal's credentials.

**Remediation:** Evaluate intent; if unwanted, delete environments and SCP deny cloud9:*.

---

### CTL.CLOUD9.ENV.PUBLIC.001

**Cloud9 Environment Has Public SSH Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Cloud9 environment is configured with CONNECT_SSH connection type, which requires the underlying EC2 instance to have a public IP address and SSH port open to the internet. This exposes the development environment to brute force attacks and credential stuffing. Use CONNECT_SSM (Systems Manager) instead, which does not require a public IP or inbound security group rules.

**Remediation:** Recreate the Cloud9 environment with CONNECT_SSM connection type. SSM does not require a public IP or inbound security group rules.

---


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

### CTL.CLOUD9.IMDS.V1.001

**Cloud9 Environment Must Enforce IMDSv2**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Cloud9 environment EC2 instance allows IMDSv1 access. IMDSv1 is vulnerable to SSRF attacks that can steal instance credentials from the metadata endpoint.

**Remediation:** Enforce IMDSv2 on the Cloud9 environment EC2 instance.

---

### CTL.CLOUD9.ROLE.OVERBROAD.001

**Cloud9 Environment Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Cloud9 environment's IAM credentials have permissions beyond what the development IDE requires. Cloud9 environments either use AWS managed temporary credentials (scoped automatically) or a manually attached instance profile. When using an instance profile, the environment needs only the specific resources the developer works with. Any wildcard actions — s3:*, iam:PassRole, sts:AssumeRole on broad targets — mean the IDE becomes an over-permissioned interactive shell.

**Remediation:** Use AWS managed temporary credentials (which are automatically scoped) instead of a custom instance profile. If a custom profile is required, scope it to the specific resources the developer needs. Remove wildcard actions.

---


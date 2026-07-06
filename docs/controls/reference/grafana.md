# Control Reference — GRAFANA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GRAFANA.AUTH.001

**Managed Grafana Workspace Not Using SSO Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2; scs_c02: 10.11; soc2: CC6.1;

An Amazon Managed Grafana workspace is not configured with IAM Identity Center (SSO) or SAML authentication. Without centralized authentication, workspace access is managed separately from the organization's identity provider, creating credential sprawl and bypassing MFA and session policies enforced by the IdP.

**Remediation:** Configure IAM Identity Center or SAML authentication for the workspace: aws grafana update-workspace-authentication --workspace-id <id> --authentication-providers AWS_SSO.

---


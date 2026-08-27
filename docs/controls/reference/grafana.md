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

### CTL.GRAFANA.ENCRYPT.CMK.001

**Managed Grafana Workspace Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

Managed Grafana workspace has encryption at rest enabled but does not use a customer-managed KMS key. The AWS-managed key provides at-rest encryption but no key-policy control and no ability to revoke access by disabling the key. If the uses_cmk field is absent the control is not-evaluable and does not fire.

**Remediation:** Create a new Grafana workspace with a customer-managed KMS key (aws grafana create-workspace --kms-key-id arn:aws:kms:...:key/...). Migrate dashboards and data sources to the new workspace.

---


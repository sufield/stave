# Control Reference — FMS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.FMS.ADMIN.001

**AWS Firewall Manager Administrator Account Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-7; scs_c02: 7.5; soc2: CC6.1, CC6.6;

AWS Firewall Manager has no administrator account configured. Without an FMS administrator, WAF rules, Shield Advanced protections, security group policies, and Network Firewall policies cannot be centrally managed across the organization. Each account must independently configure its own firewall rules, leading to inconsistent perimeter security.

**Remediation:** Associate an FMS administrator account: aws fms associate-admin-account --admin-account <security-acct>.

---

### CTL.FMS.DELIVERY.HEALTH.001

**Firewall Manager Policy Evaluation Must Be Delivering**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CA-7; nist_800_53_r5: CA-7; soc2: CC7.2;

Firewall Manager policy evaluation is not delivering compliance data from member accounts. FMS policies appear enforced — the administrator account shows the policy as active and member accounts are listed — but compliance evaluation results have stopped arriving. Member account WAF rules, security groups, or Shield protections may have drifted without the administrator account detecting the non-compliance. This is the delivery health pattern applied to centralized policy management: the policy is configured but the evaluation mechanism has failed.

**Remediation:** Check FMS policy compliance status in the administrator account. Verify member account associations are active. Check AWS Organizations integration health. Common causes: member account left the organization, FMS service-linked role was modified, or Config recorder in member accounts was disabled (FMS depends on Config for compliance evaluation).

---

### CTL.FMS.ENABLED.001

**AWS Firewall Manager Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, SI-4; soc2: CC7.2;

AWS Firewall Manager is not enabled. Firewall Manager centrally configures and manages firewall rules across accounts and resources in an organization. Without it, firewall rules must be managed individually per account.

**Remediation:** Enable AWS Firewall Manager by designating an admin account in your AWS Organization.

---

### CTL.FMS.POLICY.NONCOMPLIANT.001

**Firewall Manager Policy Has Non-Compliant Member Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-7; scs_c02: 7.5; soc2: CC6.6;

A Firewall Manager security policy has member accounts that are not compliant with the policy. Non-compliant accounts lack the firewall rules, security group configurations, or Shield protections that the policy mandates. The perimeter security posture is inconsistent across the organization.

**Remediation:** Enable auto-remediation on the FMS policy or manually apply the policy to non-compliant accounts. Review the compliance report: aws fms get-compliance-detail --policy-id <id>.

---


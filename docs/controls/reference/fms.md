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

### CTL.FMS.POLICY.NONCOMPLIANT.001

**Firewall Manager Policy Has Non-Compliant Member Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-7; scs_c02: 7.5; soc2: CC6.6;

A Firewall Manager security policy has member accounts that are not compliant with the policy. Non-compliant accounts lack the firewall rules, security group configurations, or Shield protections that the policy mandates. The perimeter security posture is inconsistent across the organization.

**Remediation:** Enable auto-remediation on the FMS policy or manually apply the policy to non-compliant accounts. Review the compliance report: aws fms get-compliance-detail --policy-id <id>.

---


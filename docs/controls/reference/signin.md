# Control Reference — SIGNIN

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SIGNIN.CONSOLE.AUTH.ENABLED.001

**Console Sign-In Authorization Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Console sign-in resource-based policy (RBP) enforcement must be enabled for the account. When disabled, any resource permission statements defining network restrictions (source IP, source VPC) have no effect — the policies exist but are not enforced, leaving the console sign-in path unrestricted.

**Remediation:** Enable console authorization via aws signin put-console-authorization-configuration --target-id <account-id> --region us-east-1.

---

### CTL.SIGNIN.CONSOLE.BYPASS.UNDOCUMENTED.001

**Console Sign-In Bypass Must Have Matching Restrictions**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

An excluded principal (bypass ARN) in the console sign-in policy must be paired with at least one resource permission statement that defines actual restrictions. A bypass ARN with no restriction statements indicates incomplete configuration — the bypass exists for a restriction that does not exist.

**Remediation:** Either add resource permission statements (source IP/VPC restrictions) that the bypass principal is exempt from, or remove the excluded principal if no restrictions are planned.

---

### CTL.SIGNIN.CONSOLE.POLICY.EMPTY.001

**Console Sign-In Policy Must Define Network Restrictions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

When console sign-in authorization is enabled, at least one resource permission statement must define network restrictions (source IP or source VPC conditions). Enforcement with no statements is a no-op — authorization is on but restricting nothing.

**Remediation:** Add at least one resource permission statement via aws signin put-resource-permission-statement with --source-ip and/or --source-vpc parameters.

---


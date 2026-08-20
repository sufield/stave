# Control Reference — SIGNIN

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SIGNIN.CONSOLE.AUTH.ENABLED.001

**Console Sign-in Authorization Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Console sign-in resource-based policy enforcement is not enabled for this account. Resource permission statements may exist defining network restrictions (source IP, source VPC) for console sign-in, but they have no effect until authorization is enabled. Without enforcement, any IAM principal with valid credentials can sign in to the console from any network — the resource-based policies are decorative. This is the console equivalent of having an SCP that is not attached to any OU.

**Remediation:** Enable console authorization enforcement for the account: aws signin put-console-authorization-configuration --target-id <account-id> --region us-east-1. Verify with aws signin get-console-authorization-configuration.

---

### CTL.SIGNIN.CONSOLE.BYPASS.UNDOCUMENTED.001

**Console Sign-in Bypass Exists Without Restrictions**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Console sign-in policy has an excluded principal (bypass ARN) but no resource permission statements define network restrictions. The bypass exists for a restriction that does not exist — someone configured a break-glass identity but never configured the network restrictions that would make the bypass meaningful. This indicates incomplete configuration: either the restrictions were removed after the bypass was set up, or the setup was abandoned mid-way.

**Remediation:** Either create resource permission statements to restrict console sign-in by network (aws signin put-resource-permission-statement), or remove the bypass principal if restrictions are not intended.

---

### CTL.SIGNIN.CONSOLE.POLICY.EMPTY.001

**Console Authorization Enabled With No Network Restrictions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Console sign-in authorization is enabled but no resource permission statements define network restrictions. The enforcement mechanism is active but restricting nothing — every console sign-in from any network is permitted, identical to having authorization disabled. This is the equivalent of enabling a firewall with an allow-all default rule and no other rules. The security team sees "enforcement enabled" in the console and believes sign-in is restricted, but the restriction set is empty.

**Remediation:** Create at least one resource permission statement with network conditions: aws signin put-resource-permission-statement --source-ip <CIDR> or --source-vpc <vpc-id>. Verify with aws signin list-resource-permission-statements.

---


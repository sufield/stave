# Control Reference — SECURITYAGENT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECURITYAGENT.NETWORK.UNRESTRICTED.001

**Security Agent Network Traffic Rules Must Restrict Targets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

AWS Security Agent has URL-based network traffic rules that do not restrict targets. The agent either has a wildcard ALLOW pattern or no DENY rules, meaning the URL-based filtering is configured but not restricting. The agent can reach any URL during execution, expanding its blast radius beyond the intended pentest scope. Network traffic rules are the application-layer complement to VPC egress — even with restricted egress, unrestricted URL rules allow the agent to probe any reachable endpoint.

**Remediation:** Add explicit DENY rules for sensitive internal endpoints. Replace wildcard ALLOW patterns with targeted URL patterns matching only the pentest target scope.

---

### CTL.SECURITYAGENT.ROLE.OVERBROAD.001

**Security Agent Service Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

AWS Security Agent service role has admin-level or wildcard permissions. The service role is the IAM role the pentest agent assumes during execution — an overbroad role gives the agent access beyond the pentest target scope. A compromised or misconfigured agent with an overbroad role can read secrets, modify infrastructure, or escalate privileges across the entire account instead of being confined to the designated target resources.

**Remediation:** Scope the service role to only the resources and actions required for the specific pentest target. Replace wildcard Resource and Action grants with explicit ARNs and action lists matching the engagement scope.

---

### CTL.SECURITYAGENT.VPC.EGRESS.001

**Security Agent VPC Must Restrict Egress**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

AWS Security Agent runs in a VPC with unrestricted egress. The agent's security group allows outbound traffic to 0.0.0.0/0, meaning the agent can reach any external endpoint. A compromised or misconfigured agent with unrestricted egress can exfiltrate data to attacker-controlled infrastructure or establish C2 communication channels. The VPC placement provides no isolation benefit when egress is unrestricted.

**Remediation:** Restrict egress security group rules to only the endpoints required for pentest target communication. Remove 0.0.0.0/0 outbound rules and replace with specific CIDR blocks or security group references for the target infrastructure.

---


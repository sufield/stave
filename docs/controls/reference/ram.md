# Control Reference — RAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.RAM.EXTERNAL.001

**RAM Resource Share Includes External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

AWS Resource Access Manager (RAM) shares resources (subnets, Transit Gateways, Route53 Resolver rules) with accounts outside the organization. Shared resources are accessible to the external account's principals — extending the network and resource boundary beyond organizational control. Unlike IAM trust policies, RAM shares operate at the resource level and can expose network infrastructure.

**Remediation:** Remove external account principals from the RAM resource share. If external sharing is required, restrict to specific account IDs and resource types. Use AWS Organizations for internal sharing.

---


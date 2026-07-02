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

### CTL.RAM.PERMISSION.001

**RAM Resource Shares Must Use Specific Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

RAM resource shares must use specific, granular permissions rather than default full access. When a resource share uses default permissions, the consuming account gets the broadest possible access to the shared resource. Custom permissions restrict actions to only what the consumer needs.

**Remediation:** Replace the default permission with a custom managed permission that grants only the specific actions required. Use aws ram create-permission to define a scoped permission, then associate it with the resource share.

---

### CTL.RAM.SCOPE.001

**RAM Resource Shares Must Restrict Resource Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

RAM resource shares must restrict the types of resources shared to only those explicitly required. Unrestricted sharing exposes all shareable resource types (subnets, Transit Gateways, Resolver rules, License Manager configs, Outposts, etc.) when only a subset is needed. Each additional shared resource type extends the blast radius of the share.

**Remediation:** Review shared resource types and remove any not explicitly needed. Use separate shares for different resource types to limit scope.

---


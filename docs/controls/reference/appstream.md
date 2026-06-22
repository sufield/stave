# Control Reference — APPSTREAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPSTREAM.INTERNET.001

**AppStream Fleets Must Disable Default Internet Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

AppStream fleets must disable default internet access. Fleets with default internet connectivity allow streaming sessions to reach the internet directly, bypassing network controls.

**Remediation:** Disable EnableDefaultInternetAccess and use VPC with NAT.

---


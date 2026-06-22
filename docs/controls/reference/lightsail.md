# Control Reference — LIGHTSAIL

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.LIGHTSAIL.DB.PUBLIC.001

**Lightsail Databases Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail managed databases must not be publicly accessible.

**Remediation:** Disable public mode on the database.

---

### CTL.LIGHTSAIL.INSTANCE.PUBLIC.001

**Lightsail Instances Must Not Expose Public Ports Broadly**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail instances with public IPs must not have firewall rules allowing broad public access to service ports.

**Remediation:** Restrict firewall rules to specific CIDR ranges.

---


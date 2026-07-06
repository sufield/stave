# Control Reference — SERVICECATALOG

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SERVICECATALOG.CONSTRAINT.001

**Service Catalog Portfolio Has No Launch Constraints**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; scs_c02: 7.4; soc2: CC6.1;

A Service Catalog portfolio has products without launch constraints. Without a launch constraint, products are launched using the end user's IAM permissions, which may be insufficient or excessive. Launch constraints specify an IAM role that Service Catalog assumes to provision the product, enforcing least privilege and consistent provisioning.

**Remediation:** Add a launch constraint to each product in the portfolio specifying a dedicated provisioning role with least-privilege permissions.

---


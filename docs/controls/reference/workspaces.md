# Control Reference — WORKSPACES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.WORKSPACES.ENCRYPT.001

**WorkSpaces Must Encrypt Volumes At Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

WorkSpaces root and user EBS volumes must be encrypted at rest.

**Remediation:** Enable volume encryption on the workspace.

---


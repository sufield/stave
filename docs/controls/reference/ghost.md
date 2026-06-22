# Control Reference — GHOST

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GHOST.TEMPORAL.PERMISSION.001

**Permission Scope Must Not Widen After Resource Deletion**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

When a policy's Resource pattern changes from a specific ARN to a broader wildcard pattern between snapshots, and a resource deletion occurred in the same window, this indicates a ghost reference was "fixed" by widening permissions. The result is broader access than before the deletion — a scope expansion disguised as cleanup.

**Remediation:** Replace the wildcard pattern with specific ARNs for the intended resources. Do not widen permissions to fix dangling references.

---

### CTL.GHOST.TEMPORAL.RESOURCE.001

**Resources Deleted Between Snapshots Must Not Have Persisting References**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

When a resource is present in snapshot N-1 but absent in snapshot N, all references to that resource's ARN must also be removed in snapshot N. A resource confirmed deleted by two independent observations (present then absent) with persisting references is the highest-confidence ghost finding — not an extractor gap but a verified deletion with orphaned references. The severity inherits from the reference type: write permissions to reclaimable resources are critical, monitoring targets are critical, read permissions are high, and configuration references are medium.

**Remediation:** Remove all references to the deleted resource's ARN from policies, triggers, configurations, and compute definitions.

---


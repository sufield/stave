# Control Reference — MQ

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MQ.PUBLIC.001

**Amazon MQ Brokers Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Amazon MQ brokers must not expose public endpoints. Public brokers allow unauthenticated or internet-based access to message queues.

**Remediation:** Disable public accessibility on the broker.

---


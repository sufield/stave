# Control Reference — NLB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.NLB.LISTENER.NOCONDITION.001

**NLB Listener Rule Has No Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4, SC-7; soc2: CC6.1, CC6.6;

Network Load Balancer listener rule has no conditions — all traffic matches unconditionally and forwards to the target group. Conditionless rules accept traffic from any source IP, port, or protocol without filtering, bypassing the network-level access control that listener rules can provide. At minimum, rules should filter by source IP CIDR for internal services or by host-header for shared listeners.

**Remediation:** Add conditions to the listener rule — source IP CIDR for internal services, or host-header/path-pattern conditions for application routing. Remove the default catch-all rule if more specific rules exist.

---

### CTL.NLB.MTLS.001

**NLB Listener Does Not Enforce Mutual TLS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-3, SC-8; soc2: CC6.1;

Network Load Balancer TLS listener does not enforce mutual TLS authentication. Without mTLS, the NLB verifies the server certificate to clients but does not verify client certificates — any client with network access can connect. For service-to-service communication, mTLS provides cryptographic identity verification at the transport layer, preventing unauthorized services from connecting even if they have network access.

**Remediation:** Enable mutual TLS authentication on the NLB listener. Configure a trust store with the CA certificate that signs client certificates, then set MutualAuthentication.Mode to "verify".

---


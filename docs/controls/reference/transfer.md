# Control Reference — TRANSFER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TRANSFER.SECPOLICY.LEGACY.001

**Transfer Family Server Must Not Use Legacy Security Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

AWS Transfer Family servers must use a current security policy, not a legacy policy such as TransferSecurityPolicy-2018-11. Legacy policies include weak cipher suites (CBC-mode ciphers, SHA1-based MACs) and may permit TLS 1.0 negotiation. AWS publishes updated security policies that remove deprecated ciphers; servers pinned to old policies expose file transfer sessions to downgrade risks. SFTP, FTPS, and FTP-over-TLS sessions carry credentials and file contents — weak cipher negotiation on the transfer endpoint is a direct data exposure vector. The same pattern as CTL.APIGATEWAY.DOMAIN.TLS.POLICY.STALE.001 and CTL.ELB.TLS.CUSTOM.WEAKCIPHER.001.

**Remediation:** Update the server security policy to the current AWS recommendation: aws transfer update-server --server-id <id> --security-policy-name TransferSecurityPolicy-2024-01. Verify that all SFTP/FTPS clients can negotiate with the modern cipher list before switching production servers. Older clients may require TLS-stack upgrades.

---


# Control Reference — TRANSFER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.TRANSFER.ENCRYPT.REST.001

**Transfer Family Server Must Have At-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

AWS Transfer Family servers must encrypt stored data at rest. Transfer Family can store uploaded files on S3 or EFS backends. While S3 and EFS have their own encryption controls, the Transfer server configuration itself determines whether server-managed storage (workflow intermediate files, AS2 payloads, connector temporary files) is encrypted. Without at-rest encryption, data in transit through the server's managed storage is exposed to anyone with disk or snapshot access. This complements the TLS controls (CTL.TRANSFER.SECPOLICY.LEGACY.001) which protect data in transit over the network.

**Remediation:** Enable at-rest encryption on the Transfer Family server or ensure the underlying S3 bucket or EFS file system has encryption enabled. For server-managed storage, configure a KMS key for the server's encryption settings.

---

### CTL.TRANSFER.EXTERNAL.DESTINATION.001

**Transfer Family Must Not Send Data to External Endpoints**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

No Transfer Family server should have workflow steps that target S3 buckets or EFS in external accounts, or SFTP/FTP destinations at external hosts. Transfer Family provides managed file transfer — an attacker can configure it to deliver files to an external SFTP server. Linked to Muddled Libra campaigns (2024) documented by Wiz. Technique: Wiz "Exfiltration via AWS Transfer".

**Remediation:** Verify the destination is legitimate. If not, remove the workflow step immediately. Restrict transfer:CreateWorkflow via SCP.

---

### CTL.TRANSFER.SECPOLICY.LEGACY.001

**Transfer Family Server Must Not Use Legacy Security Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

AWS Transfer Family servers must use a current security policy, not a legacy policy such as TransferSecurityPolicy-2018-11. Legacy policies include weak cipher suites (CBC-mode ciphers, SHA1-based MACs) and may permit TLS 1.0 negotiation. AWS publishes updated security policies that remove deprecated ciphers; servers pinned to old policies expose file transfer sessions to downgrade risks. SFTP, FTPS, and FTP-over-TLS sessions carry credentials and file contents — weak cipher negotiation on the transfer endpoint is a direct data exposure vector. The same pattern as CTL.APIGATEWAY.DOMAIN.TLS.POLICY.STALE.001 and CTL.ELB.TLS.CUSTOM.WEAKCIPHER.001.

**Remediation:** Update the server security policy to the current AWS recommendation: aws transfer update-server --server-id <id> --security-policy-name TransferSecurityPolicy-2024-01. Verify that all SFTP/FTPS clients can negotiate with the modern cipher list before switching production servers. Older clients may require TLS-stack upgrades.

---


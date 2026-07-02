# Control Reference — ACM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACM.CERT.EXPIRY.001

**ACM Imported Certificates Must Not Be Near Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

SSL/TLS certificates imported into ACM must not be within 30 days of expiry or already expired. ACM automatically renews certificates it provisions (AMAZON_ISSUED) but does not renew imported certificates. Imported certificates expire silently on their expiry date with no enforcement mechanism — services continue serving traffic on an expired certificate until clients reject it. An expired certificate on a production load balancer or CloudFront distribution causes TLS negotiation failures for all clients that enforce certificate validity. For HIPAA and PCI-DSS environments, serving traffic on an expired certificate is a direct compliance violation. This control evaluates only IMPORTED certificates — AMAZON_ISSUED certificates are auto-renewed and out of scope.

**Remediation:** Renew or replace the imported certificate. Import the new certificate into ACM via aws acm import-certificate. If the certificate was originally from a private CA, re-issue from the CA and re-import. Consider migrating to an ACM-managed certificate (AMAZON_ISSUED) for automatic renewal — ACM provisions free public certificates for domains validated via DNS or email. After importing the new certificate, verify the associated services (load balancers, CloudFront distributions, API Gateway domains) are serving the updated certificate.

---

### CTL.ACM.CERT.VALIDATION.001

**ACM Certificates Must Use DNS Validation**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-17; scs_c02: 6.2; soc2: CC6.1;

ACM certificates should use DNS validation, not email validation. Email validation requires manual intervention for each renewal — if the domain contact email is stale, renewal fails silently and the certificate expires. DNS validation enables automatic renewal as long as the CNAME record exists, eliminating human-dependent renewal processes.

**Remediation:** Re-request the certificate with DNS validation. Add the CNAME record ACM provides to your DNS zone. This enables automatic renewal without human intervention.

---

### CTL.ACM.KEY.ALGORITHM.001

**ACM Certificates Must Use Strong Key Algorithms**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-13; soc2: CC6.7;

ACM certificates must use RSA-2048+ or ECDSA P-256+ key algorithms. Weak algorithms (RSA-1024, ECDSA P-192) are vulnerable to factoring or discrete logarithm attacks.

**Remediation:** Request a new certificate with RSA-2048 or ECDSA P-256.

---

### CTL.ACM.RENEWAL.001

**ACM Certificate Renewal Must Not Be In Failed State**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

ACM-managed certificates must not be in a failed renewal state. When ACM cannot auto-renew a certificate (DNS validation record removed, domain no longer resolves, CAA record blocks issuance), the certificate will expire on its expiry date. A failed renewal requires manual intervention — the certificate will not self-heal.

**Remediation:** Check the renewal status: aws acm describe-certificate. Common causes: DNS CNAME validation record was deleted, domain DNS is not resolving, CAA record blocks ACM issuance. Fix the underlying cause and ACM will retry renewal automatically.

---

### CTL.ACM.TRANSPARENCY.001

**ACM Certificates Must Enable Certificate Transparency Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

ACM-issued certificates must have Certificate Transparency (CT) logging enabled. CT logging publishes certificates to public logs, enabling detection of unauthorized certificate issuance for the domain.

**Remediation:** Enable CT logging when requesting or renewing the certificate.

---


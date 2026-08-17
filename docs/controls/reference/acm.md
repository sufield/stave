# Control Reference — ACM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACM.ACME.EAB.NOEXPIRY.001

**ACME EAB Credential Must Have Expiration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

ACME External Account Binding credential has no expiration — a stolen EAB KeyId/MacKey provides indefinite certificate issuance capability for every pre-approved domain on the endpoint. EAB credentials are bearer tokens: anyone with the MacKey can issue certificates. Without an expiration, a compromised credential works forever. Same principle as IAM access key rotation — credentials must have a lifetime.

**Remediation:** Set an expiration on the EAB credential. Rotate EAB credentials on a schedule aligned with your certificate lifecycle (e.g., 90 days). Store the MacKey in Secrets Manager with automatic rotation.

---

### CTL.ACM.ACME.EAB.PLAINTEXT.001

**ACME EAB MacKey Must Be Stored in Secrets Manager**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

ACME EAB MacKey is not stored in Secrets Manager — the credential may be hardcoded in client configuration, CI/CD variables, or Kubernetes secrets without rotation or access logging. The MacKey is a bearer credential that grants certificate issuance capability for every domain on the endpoint. AWS recommends storing the MacKey in Secrets Manager for rotation, access logging, and least-privilege access control.

**Remediation:** Store the EAB MacKey in AWS Secrets Manager. Configure automatic rotation and restrict access via IAM policy to only the ACME client principals that need it. Update client configuration to retrieve the MacKey from Secrets Manager at runtime.

---

### CTL.ACM.ACME.SCOPE.WILDCARD.001

**ACM ACME Endpoint Domain Scope Must Not Use Wildcards**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

ACM ACME endpoint domain scope must not contain wildcard patterns. An ACME endpoint scoped to *.example.com allows any authorized ACME client to request certificates for any subdomain. If the endpoint serves a single application (app.example.com), the wildcard scope is a blast-radius amplifier: a compromised ACME client can issue certificates for domains it should not control. Exact domain names in the scope field limit issuance to the intended services.

**Remediation:** Restrict the ACME endpoint's domain scope to the specific domains that need certificate issuance. Replace *.example.com with the exact domain names (app.example.com, api.example.com). If wildcard scope is operationally required, document the justification and tighten IAM policies on the endpoint to limit which principals can request certificates.

---

### CTL.ACM.ACME.SPRAWL.001

**Account Has Excessive ACM ACME Endpoints**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC8.1;

Account has more ACME endpoints than the governance threshold. Each ACME endpoint is an independent certificate issuance point with its own domain scope, wildcard policy, and client access. Without centralized governance, application teams create endpoints ad hoc — each with different policies, different scopes, and different levels of oversight. The resulting sprawl makes certificate issuance unauditable: no single team knows which endpoints exist, what domains they cover, or who has access. Same accumulation pattern as CTL.SQS.POLICY.SPRAWL.001. The threshold is a heuristic; adjust per organization size.

**Remediation:** Audit existing ACME endpoints and consolidate where possible. Establish a naming convention and tagging policy for ACME endpoints. Consider a central platform team that provisions endpoints with approved domain scopes and wildcard policies, rather than allowing each application team to create its own.

---

### CTL.ACM.ACME.WILDCARD.001

**ACM ACME Endpoint Must Not Allow Wildcard Certificate Issuance**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

ACM ACME endpoint must not permit wildcard certificate issuance. A wildcard certificate (*.example.com) covers every subdomain under the parent domain. One compromised private key or one leaked certificate exposes every subdomain to impersonation. ACME endpoints can enforce policies on wildcard usage — disabling wildcard issuance forces per-subdomain certificates, limiting blast radius to the single service whose key is compromised.

**Remediation:** Set the endpoint's wildcard policy to DENY. Issue individual certificates for each subdomain instead of wildcard certificates. If wildcard issuance is operationally required (e.g., a CDN serving many subdomains), document the justification, ensure the private key is stored in a hardware security module, and monitor Certificate Transparency logs for unexpected issuance.

---

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

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-17; pci_dss_v4.0: 4.2.1; scs_c02: 6.2; soc2: CC6.1;

ACM certificates must use DNS validation, not email validation. Email validation is deprecated — AWS will stop supporting email validation for certificate renewal on September 30, 2027. After that date, ACM will not renew email-validated certificates. When the certificate expires, TLS terminates and the associated service becomes unreachable. This is the ghost archetype: the certificate works today, the renewal mechanism is deprecated, and the failure will be silent — ACM won't renew, the certificate expires, no alert fires because certificate expiration isn't a security finding in most monitoring stacks. Migrate to DNS validation using UpdateCertificateOptions before the deadline.

**Remediation:** Migrate to DNS validation: aws acm update-certificate-options --certificate-arn <arn> --options CertificateTransparencyLoggingPreference=ENABLED. If the certificate cannot be updated in place, re-request with DNS validation, add the CNAME record ACM provides to your DNS zone, and update the resource associations to point to the new certificate ARN.

---

### CTL.ACM.IMPORT.RENEWAL.ABSENT.001

**Imported ACM Certificate Has No Renewal Automation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-12; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Imported ACM certificate has no renewal automation. ACM auto-renews certificates it issues via DNS or email validation, but imported certificates expire on their expiry date with no automatic renewal. If nobody tracks the expiry and manually reimports a renewed certificate, the certificate expires and dependent services (ALB, CloudFront, API Gateway) fail TLS handshakes. Distinct from CTL.ACM.RENEWAL.001 which detects failed renewal of Amazon-issued certificates; this control detects imported certificates that have no renewal mechanism at all.

**Remediation:** Either replace the imported certificate with an ACM-issued certificate (which auto-renews via DNS validation) or implement renewal automation: an EventBridge rule monitoring the DaysToExpiry metric with a Lambda that reimports the renewed certificate. Verify the certificate's NotAfter date and set alerts at 90, 30, and 7 days before expiry.

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


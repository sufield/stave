# Control Reference — ACMPCA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ACMPCA.CRL.001

**Private CA Has No CRL Distribution Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.7;

An ACM Private CA does not have a Certificate Revocation List (CRL) distribution point configured. Without CRL or OCSP, revoked certificates cannot be validated by relying parties, meaning compromised certificates remain trusted until expiry.

**Remediation:** Configure CRL distribution: aws acm-pca update-certificate-authority --certificate-authority-arn <arn> --revocation-configuration CrlConfiguration={Enabled=true, S3BucketName=<bucket>}.

---

### CTL.ACMPCA.CROSSACCOUNT.001

**ACM-PCA Must Not Issue Certificates to External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S05; soc2: CC6.1; subtractive_tier: deletion;

ACM Private CA resource policies must not permit acm-pca:IssueCertificate from principals outside the organization. An attacker with Route53 modification permissions plus ACM-PCA access can issue certificates for internal domains and intercept API traffic. Technique: hackingthe.cloud Route53 modification privilege escalation via ACM-PCA.

**Remediation:** Restrict the resource policy to allow acm-pca:IssueCertificate only from principals within the organization. Use aws:PrincipalOrgID conditions.

---

### CTL.ACMPCA.KEYALGORITHM.001

**Private CA Uses Weak Key Algorithm**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-12, SC-13; soc2: CC6.7;

An ACM Private CA uses RSA 2048-bit keys. For root and subordinate CAs with long validity periods, RSA 4096 or EC P384 provides better long-term security margins.

**Remediation:** Create a new CA with a stronger key algorithm: aws acm-pca create-certificate-authority --certificate-authority-configuration KeyAlgorithm=RSA_4096 (or EC_prime256v1 / EC_secp384r1).

---

### CTL.ACMPCA.STATUS.001

**Private CA Not in Active State**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.7;

An ACM Private CA is not in ACTIVE state. A CA in DISABLED, PENDING_CERTIFICATE, DELETED, EXPIRED, or FAILED state cannot issue certificates, breaking downstream services that depend on it for TLS or mutual authentication.

**Remediation:** Check the CA status and resolve: aws acm-pca describe-certificate-authority --certificate-authority-arn <arn>. If PENDING_CERTIFICATE, import the signed CA certificate. If DISABLED, re-enable with update-certificate-authority.

---


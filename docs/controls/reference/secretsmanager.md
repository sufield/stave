# Control Reference — SECRETSMANAGER

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECRETSMANAGER.ACCESS.001

**Secrets Must Have Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); owasp_nhi: NHI9; soc2: CC6.1;

Secrets Manager secrets must have automatic rotation enabled. Long-lived secrets that are never rotated increase the blast radius of credential leaks and prevent timely revocation.

**Remediation:** Configure automatic rotation with a Lambda function. Run: aws secretsmanager rotate-secret --secret-id xxx --rotation-lambda-arn arn:aws:lambda:... --rotation-rules AutomaticallyAfterDays=90

---

### CTL.SECRETSMANAGER.ENCRYPT.001

**Secrets Must Be Encrypted with Customer-Managed KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Secrets Manager secrets must be encrypted with a customer-managed KMS key. The default AWS-managed key does not support key revocation or cross-account key policies needed for breach response.

**Remediation:** Recreate the secret with a customer-managed KMS key specified. Secrets Manager does not allow changing the encryption key after creation.

---

### CTL.SECRETSMANAGER.ENCRYPT.KMS.POLICY.001

**KMS Key Policy for Secrets Manager Encryption Is Overly Broad**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-13, IA-5(7); pci_dss_v4.0: 3.6.1; soc2: CC6.1;

The KMS key used to encrypt a Secrets Manager secret has an overly broad key policy — kms:Decrypt granted to the account root, a wildcard principal, or a broad IAM pattern. An overly broad key policy undermines encryption: any matching principal can decrypt the secret value, bypassing Secrets Manager's resource policy and IAM controls entirely. Same cross-property invariant as CTL.S3.ENCRYPT.KMS.POLICY.001 applied to Secrets Manager: the secret passes the CMK-encrypted check but the key policy makes the encryption cosmetic. The collector pre-computes kms_key_policy_broad by joining the secret's KmsKeyId to the KMS key's policy analysis.

**Remediation:** Scope the KMS key policy to the specific principals that need access. Use kms:ViaService condition to restrict usage to secretsmanager.amazonaws.com. Remove kms:* grants and limit kms:Decrypt to authorized consumers only.

---

### CTL.SECRETSMANAGER.INCOMPLETE.001

**Complete Data Required for Secrets Manager Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required Secrets Manager properties. A safety assessment cannot be completed without secret configuration data.

**Remediation:** Ensure the extractor calls aws secretsmanager describe-secret and maps the response to the secret observation properties.

---

### CTL.SECRETSMANAGER.POLICY.PUBLIC.001

**Secrets Manager Secret Must Not Have Public Resource Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; owasp_nhi: NHI5; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Secrets Manager resource policies must not grant secretsmanager:GetSecretValue or secretsmanager:* to Principal "*" or to unauthenticated principals without scoping conditions. Public secret access allows any AWS principal to retrieve the secret value, which typically contains database credentials, API keys, or certificates.

**Remediation:** Restrict the resource policy to specific IAM roles or accounts. Remove any statements with Principal "*". For cross-account access, add aws:PrincipalOrgID or aws:SourceAccount conditions.

---


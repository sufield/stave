# Control Reference — SES

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SES.IDENTITY.DKIM.001

**SES Identity Must Have DKIM Signing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-8; soc2: CC6.6;

SES sending identities (domains and email addresses) must have DomainKeys Identified Mail (DKIM) signing enabled. Without DKIM, emails sent through SES lack a cryptographic signature that receiving mail servers use to verify the sender's identity. An attacker who compromises IAM credentials with ses:SendEmail permission can send phishing emails that appear to originate from the organization's domain. DKIM signing combined with a strict DMARC policy causes receiving servers to reject unsigned emails, limiting the blast radius of compromised SES credentials. Stratus Red Team's ses-enumerate technique specifically checks for SES identities that lack DKIM — these are the identities an attacker would abuse for phishing campaigns.

**Remediation:** Enable DKIM signing for the SES identity using Easy DKIM or BYODKIM. For domains, also configure SPF (via SES MAIL FROM) and a DMARC policy with p=reject. Verify DKIM status shows "Success" in the SES console before relying on it.

---


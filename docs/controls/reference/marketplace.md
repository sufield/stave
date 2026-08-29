# Control Reference — MARKETPLACE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MARKETPLACE.AGREEMENT.UNAPPROVED.001

**Active Marketplace Agreement With External Seller**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

An active Marketplace agreement exists with a third-party seller (proposer account differs from the organization's accounts). Active agreements with external sellers represent ongoing financial commitments and potential data-sharing arrangements. The r/aws incident demonstrated that a single agreement acceptance can generate irrecoverable charges via seller-side consumption metering.
First-party AWS agreements (no proposer account) are SILENT for this control — they represent AWS services, not third-party risk.

**Remediation:** Review the agreement via aws marketplace-agreement search-agreements. If the agreement is unauthorized, cancel it immediately. Enable Private Marketplace (CTL.MARKETPLACE.PRIVATE.ENABLED.001) and SCP deny (CTL.ORG.SCP.MARKETPLACE.001) to prevent future unauthorized agreements.

---

### CTL.MARKETPLACE.PRIVATE.ENABLED.001

**Private Marketplace Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

Organization does not have a Private Marketplace experience in LIVE status. Without Private Marketplace, any principal with subscription permissions can subscribe to any listing in the public AWS Marketplace catalog. Private Marketplace restricts subscribable products to an approved set maintained by the procurement team.

**Remediation:** Create a Private Marketplace experience via the AWS Marketplace Catalog API and set it to LIVE status. Add approved products to the experience before enabling.

---


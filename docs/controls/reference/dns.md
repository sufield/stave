# Control Reference — DNS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DNS.DANGLING.001

**DNS Records Must Not Point to Unclaimed Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records (CNAME, ALIAS, A) that reference external cloud resources must resolve to resources that exist and are owned by the organization. A dangling DNS record pointing to a deleted or unclaimed resource enables subdomain takeover — the attacker claims the resource and serves content under the organization's domain.

**Remediation:** Either claim the target resource in your cloud account to block takeover, or delete the DNS record that points to the unclaimed resource. Audit all DNS zones for records pointing to decommissioned infrastructure.

---

### CTL.DNS.DANGLING.002

**DNS Records to Cloud Storage Must Resolve to Owned Buckets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records that reference cloud storage endpoints (S3, GCS, Azure Blob) must resolve to buckets that exist and are owned by the organization. Storage bucket names are globally unique — a deleted bucket's name can be claimed by any account, enabling content injection under a trusted domain.

**Remediation:** Create the bucket in your cloud account to claim the name, or remove the DNS record. For software distribution URLs, update documentation to point to the current distribution endpoint.

---

### CTL.DNS.DANGLING.003

**DNS Records to Software Distribution Must Resolve to Owned Endpoints**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure

DNS records or URLs that reference software distribution endpoints (package repositories, binary downloads, update servers) must resolve to resources owned by the organization. Supply chain takeover through dangling distribution references delivers executable code to systems that trust the source.

**Remediation:** Claim the resource to block takeover. Update all documentation, install guides, and CI pipelines to reference the current distribution URL. Search community forums and cached tutorials for outdated references.

---


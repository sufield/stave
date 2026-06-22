# Control Reference — ELASTICACHE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ELASTICACHE.AUTH.001

**Redis AUTH Token Must Be Set**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ElastiCache Redis clusters must have an AUTH token configured. Without AUTH, any client with network access can read and write data. Combined with a missing VPC or open security group, this creates an unauthenticated database exposure — the same pattern as the Darkbeam Elasticsearch breach.

**Remediation:** Set an AUTH token using aws elasticache modify-replication-group --auth-token. Ensure transit encryption is also enabled (required for AUTH). Rotate the token periodically.

---

### CTL.ELASTICACHE.ENCRYPT.REST.001

**ElastiCache Redis Must Have At-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

ElastiCache Redis clusters must have at-rest encryption enabled to protect cached data (sessions, credentials, application state) stored on disk.

**Remediation:** Create a new cluster with at-rest encryption enabled (cannot be changed on existing clusters).

---

### CTL.ELASTICACHE.INCOMPLETE.001

**Complete Data Required for ElastiCache Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required ElastiCache properties.

**Remediation:** Ensure the extractor calls aws elasticache describe-replication-groups and maps TransitEncryptionEnabled to the cache observation properties.

---

### CTL.ELASTICACHE.TRANSIT.001

**ElastiCache Must Have In-Transit Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

ElastiCache clusters must have in-transit encryption enabled. Without TLS, cache traffic travels in plaintext between the application and the cache nodes, exposing cached PHI data.

**Remediation:** In-transit encryption can only be enabled at cluster creation. Create a new replication group with TransitEncryptionEnabled=true and migrate data from the existing cluster.

---


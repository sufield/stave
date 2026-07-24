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

### CTL.ELASTICACHE.BACKUP.001

**ElastiCache Redis Automatic Backups Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

ElastiCache Redis replication groups must have automatic backups enabled with a retention period of at least 1 day. Without automatic backups, a node failure, accidental FLUSHALL, or ransomware event destroys all cached data with no recovery path. ElastiCache backups are RDB snapshots stored in S3 — they capture the full dataset at a point in time and can restore to a new replication group. A retention period of 0 disables automatic backups entirely. Every comparable database service (RDS, DocumentDB, Neptune, DynamoDB) enforces automated backups; ElastiCache Redis supports them but does not enable them by default.

**Remediation:** Enable automatic backups by setting the snapshot retention limit to at least 1 day: aws elasticache modify-replication-group --replication-group-id <id> --snapshot-retention-limit 7 --apply-immediately. For compliance workloads, set retention to match your RPO requirement (max 35 days).

---

### CTL.ELASTICACHE.CLUSTER.PUBLIC.001

**ElastiCache Cluster Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, SC-7; soc2: CC6.1, CC6.6;

ElastiCache cluster or replication group is configured as publicly accessible. ElastiCache Redis and Memcached clusters should be VPC-internal only. A publicly accessible cluster exposes cached data (session tokens, API responses, user data) to the internet. Even with AUTH enabled, public network exposure increases the attack surface — brute-force attacks, protocol vulnerabilities, and credential stuffing all become possible. Scott Piper's aws_exposable_resources notes ElastiCache as a network-exposable resource type.

**Remediation:** Disable public accessibility on the cluster. Deploy ElastiCache clusters in private subnets only and access via VPC peering or VPN.

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

### CTL.ELASTICACHE.ENGINE.EOL.001

**ElastiCache Engine Version Must Not Be End-of-Life**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

ElastiCache clusters must not run engine versions that have reached end-of-life. AWS publishes a deprecation calendar per engine major version; clusters on a deprecated version no longer receive security patches and will eventually be force-upgraded during a maintenance window the operator did not choose. Redis 5.x reached EOL in 2024, Redis 6.0 in 2024, and Redis 6.2 is approaching EOL. Memcached 1.5.x is EOL. Unlike RDS, ElastiCache does not have a separate auto-minor-upgrade toggle — the engine version is the sole indicator of patch currency. Running an EOL engine version means known CVEs in the cache layer remain unpatched, and any data transiting the cache (session tokens, API responses, feature flags) is processed by unmaintained code.

**Remediation:** Upgrade the cluster to a supported engine version. For Redis, upgrade to Redis 7.x. For Memcached, upgrade to 1.6.x. Use aws elasticache modify-replication-group --engine-version <ver> with a scheduled maintenance window to minimize impact. Test application compatibility with the new engine version before upgrading production — major version upgrades may change command behavior or remove deprecated commands.

---

### CTL.ELASTICACHE.IAM.AUTH.001

**ElastiCache Redis Must Use IAM Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ElastiCache Redis 7+ clusters should use IAM authentication instead of static AUTH tokens. IAM auth provides automatic credential rotation, fine-grained access control per user, and CloudTrail audit of authentication events. Static AUTH tokens require manual rotation and provide only cluster-level access control — any client with the token has full read/write access.

**Remediation:** Enable IAM authentication on the replication group. Create ElastiCache users with IAM authentication type and associate them with a user group attached to the cluster. Update application connection code to use IAM-generated auth tokens.

---

### CTL.ELASTICACHE.INCOMPLETE.001

**Complete Data Required for ElastiCache Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required ElastiCache properties.

**Remediation:** Ensure the extractor calls aws elasticache describe-replication-groups and maps TransitEncryptionEnabled to the cache observation properties.

---

### CTL.ELASTICACHE.MEMCACHED.EOL.001

**ElastiCache Memcached Version Must Not Be End-of-Life**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

ElastiCache Memcached clusters must not run engine versions that have reached end-of-life. Memcached 1.5.x and earlier are EOL and no longer receive security patches from AWS. Unlike Redis, Memcached has no authentication layer — the only protection is network isolation, making patch currency critical. A Memcached cluster on an EOL version processes cached data (session tokens, API responses) with unmaintained code. AWS will eventually force-upgrade clusters on deprecated versions during a maintenance window the operator did not schedule.

**Remediation:** Upgrade the cluster to Memcached 1.6.x. Use aws elasticache modify-cache-cluster --engine-version 1.6.22 with a scheduled maintenance window. Memcached major version upgrades are generally backward compatible — test your application's cache client against 1.6.x before upgrading production.

---

### CTL.ELASTICACHE.RENAME.COMMANDS.001

**ElastiCache Redis Must Rename Dangerous Commands**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

ElastiCache Redis clusters must rename or disable dangerous commands (FLUSHALL, FLUSHDB, CONFIG, DEBUG, KEYS). These commands allow any authenticated client to wipe all data, reconfigure the server, or enumerate all keys. An attacker who gains cache access — through a compromised application or broad security group — can use these commands for data destruction or reconnaissance. Renaming them to unpredictable strings mitigates this without breaking normal operations.

**Remediation:** Set the rename-commands parameter in the Redis parameter group to rename FLUSHALL, FLUSHDB, CONFIG, DEBUG, and KEYS to empty strings or random values.

---

### CTL.ELASTICACHE.SG.BROAD.001

**ElastiCache Cluster Security Group Must Not Allow Broad Ingress**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

ElastiCache cluster security group must restrict ingress to specific application security groups or CIDR blocks. A security group allowing 0.0.0.0/0 on the Redis/Memcached port exposes the cache to any host with network access. Even with AUTH enabled, broad ingress increases the attack surface for brute- force and network-level exploits.

**Remediation:** Restrict the security group to allow ingress only from application security groups or specific CIDR blocks that need cache access. Remove 0.0.0.0/0 rules on ports 6379 (Redis) and 11211 (Memcached).

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


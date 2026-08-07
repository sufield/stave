# Control Reference — MEMORYDB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MEMORYDB.AUTH.REQUIRED.001

**MemoryDB Cluster Must Require Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2; soc2: CC6.1;

MemoryDB cluster does not require ACL-based authentication. Without authentication, any client with network access to port 6379 can execute Redis commands against the cluster. MemoryDB stores durable data — session state, feature stores, real-time caches — unauthenticated access enables data theft, poisoning, and lateral movement from compromised compute within the VPC.

**Remediation:** Enable ACL-based authentication on the MemoryDB cluster. Create ACL users with strong passwords and assign the ACL to the cluster. Remove the default open-access ACL.

---

### CTL.MEMORYDB.BACKUP.CONFIGURED.001

**MemoryDB Cluster Must Have Snapshots Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; pci_dss_v4.0: 3.4; soc2: A1.2;

MemoryDB cluster does not have snapshot (backup) configured. MemoryDB is a durable Redis-compatible store — without snapshots, cluster failure or accidental FLUSHALL results in permanent data loss. MemoryDB supports automatic daily snapshots with configurable retention.

**Remediation:** Enable automatic snapshots on the MemoryDB cluster with a retention period appropriate to the data's recovery requirements.

---

### CTL.MEMORYDB.ENCRYPT.REST.001

**MemoryDB Cluster Must Be Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

MemoryDB for Redis clusters must have encryption at rest enabled. MemoryDB persists data to a distributed transaction log for durability — unlike ElastiCache, data survives node restarts. Without encryption at rest the transaction log and snapshot data sit in cleartext. MemoryDB is positioned as a durable primary database, not a cache, so unencrypted storage exposes the full dataset.

**Remediation:** Encryption at rest must be set at cluster creation and cannot be changed afterward. Create a new cluster with TLSEnabled and KmsKeyId specified, restore from snapshot, then update application endpoints and delete the unencrypted cluster.

---

### CTL.MEMORYDB.LOG.SLOW.001

**MemoryDB Cluster Must Have Slow Log Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

MemoryDB cluster does not have slow log delivery enabled. Slow logs capture Redis commands that exceed a configurable latency threshold. Without slow log delivery, performance degradation from expensive commands and potential abuse patterns such as key enumeration go undetected. MemoryDB clusters hold durable Redis data — visibility into command patterns is essential for detecting data theft or poisoning.

**Remediation:** Enable slow log delivery for the MemoryDB cluster. Configure delivery to CloudWatch Logs or Kinesis Data Firehose to capture slow commands.

---

### CTL.MEMORYDB.SG.BROAD.001

**MemoryDB Cluster Security Group Must Not Allow Broad Ingress**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

MemoryDB cluster security group must restrict ingress to specific application security groups or CIDR blocks. A security group allowing 0.0.0.0/0 on port 6379 exposes the cluster to any host with network access. MemoryDB uses the same Redis protocol and default port as ElastiCache Redis — broad ingress enables the same lateral movement vector from compromised compute within the VPC.

**Remediation:** Restrict the security group to allow ingress only from application security groups or specific CIDR blocks that need cluster access. Remove 0.0.0.0/0 rules on port 6379.

---


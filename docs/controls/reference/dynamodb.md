# Control Reference — DYNAMODB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DYNAMODB.ACCESS.EXPORT.001

**IAM Policy Grants Unrestricted DynamoDB Export Permission**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.1; soc2: CC6.1;

IAM policy grants dynamodb:ExportTableToPointInTime without resource restriction or condition keys. This permission allows bulk export of the entire table to S3 in a single API call — every item and every attribute, in DynamoDB JSON or Amazon Ion format. Unlike GetItem, Query, or Scan, which retrieve items individually or by predicate, ExportTableToPointInTime retrieves the full table content without item-level filtering. Combined with write access to an S3 bucket, this is a complete data exfiltration path: the entire table can be extracted in minutes. The permission should be restricted to specific table ARNs and should require a condition key limiting the destination S3 bucket.

**Remediation:** Restrict the permission to specific table ARNs: "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/SPECIFIC_TABLE" Add a condition restricting the destination bucket: "Condition": {"StringEquals": {
  "dynamodb:tableArn": "arn:aws:dynamodb:REGION:ACCOUNT:table/SPECIFIC_TABLE"
}}. Review CloudTrail for recent ExportTableToPointInTime calls to identify any exports that may have exfiltrated data.

---

### CTL.DYNAMODB.ALARM.READCAPACITY.001

**No CloudWatch Alarm for DynamoDB Read Capacity Approaching Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

Provisioned-capacity DynamoDB table has no CloudWatch alarm monitoring ConsumedReadCapacityUnits approaching the provisioned limit. An alarm at 80% of provisioned capacity provides lead time to scale before throttling begins. Without it, the only signal of capacity exhaustion is throttling itself — by which point reads are already being rejected. This control fires only on PROVISIONED tables; on-demand tables have no provisioned limit to approach.

**Remediation:** Create a CloudWatch alarm on the AWS/DynamoDB ConsumedReadCapacityUnits metric scoped to this table at 80% of provisioned read capacity, with SNS notification to the operations team. Pair with auto-scaling so capacity is added before throttling begins. For tables with on-demand capacity mode, this alarm does not apply — switch to the ThrottledRequests alarm instead.

---

### CTL.DYNAMODB.ALARM.SYSTEMERRORS.001

**No CloudWatch Alarm for DynamoDB System Errors**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the SystemErrors metric for this DynamoDB table. SystemErrors are HTTP 5xx responses from DynamoDB itself — infrastructure-level failures the application cannot resolve through retry alone. Without an alarm, internal DynamoDB failures are invisible until application error rates spike.

**Remediation:** Create a CloudWatch alarm on the AWS/DynamoDB SystemErrors metric scoped to this table, threshold > 0 over a short evaluation window, with SNS notification to the operations team. SystemErrors that persist warrant an AWS Support case — the application cannot fix infrastructure-level failures.

---

### CTL.DYNAMODB.ALARM.THROTTLE.001

**No CloudWatch Alarm for DynamoDB Throttled Requests**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the DynamoDB ThrottledRequests metric for this table. Throttled requests mean reads or writes are being rejected by the service. For provisioned tables this indicates capacity exhaustion; for on-demand tables it indicates exceeding the per-partition limit. Without an alarm, throttling escalates from occasional rejected requests to sustained data loss (writes without retry) or latency degradation without notification.

**Remediation:** Create a CloudWatch alarm on the AWS/DynamoDB ThrottledRequests metric scoped to this table, threshold > 0 over a short evaluation window (1-5 minutes), with SNS notification to the operations team. Pair the alarm with application-level retry with exponential backoff so transient throttling does not become data loss.

---

### CTL.DYNAMODB.ALARM.WRITECAPACITY.001

**No CloudWatch Alarm for DynamoDB Write Capacity Approaching Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

Provisioned-capacity DynamoDB table has no CloudWatch alarm monitoring ConsumedWriteCapacityUnits approaching the provisioned limit. Write throttling without retry logic causes data loss — the application receives a ProvisionedThroughputExceededException and the write is dropped. An 80%-capacity alarm provides lead time to scale before throttling begins. This control fires only on PROVISIONED tables; on-demand tables have no provisioned limit to approach.

**Remediation:** Create a CloudWatch alarm on the AWS/DynamoDB ConsumedWriteCapacityUnits metric scoped to this table at 80% of provisioned write capacity, with SNS notification to the operations team. Pair with auto-scaling so capacity is added before throttling begins. For tables with on-demand capacity mode, this alarm does not apply — switch to the ThrottledRequests alarm instead.

---

### CTL.DYNAMODB.AUDIT.DATAEVENTS.001

**DynamoDB Table Has No CloudTrail Data Event Coverage**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1.7; soc2: CC7.1;

DynamoDB table is not covered by any CloudTrail trail with data events enabled. Management events (CreateTable, DeleteTable, UpdateTable) are logged by default, but data events — the actual reads and writes to items (GetItem, PutItem, UpdateItem, DeleteItem, Query, Scan, BatchGetItem, BatchWriteItem) — are not logged unless explicitly enabled. DynamoDB has no other built-in audit log: CloudTrail data events are the only item-level audit trail. Without them, unauthorized data access is invisible.

**Remediation:** Add a CloudTrail data event selector that includes this table: event category Data, resource type AWS::DynamoDB::Table, ARN matching this table, with read/write type All. Verify the trail is delivering events to S3 and CloudWatch Logs.

---

### CTL.DYNAMODB.BACKUP.001

**DynamoDB Tables Must Have Backup Plan**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

DynamoDB tables must be included in a backup plan.

**Remediation:** Add table to AWS Backup plan or enable PITR.

---

### CTL.DYNAMODB.CAPACITY.NOSCALING.001

**Provisioned DynamoDB Table Has No Auto-Scaling**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-13; soc2: A1.1;

DynamoDB table uses provisioned capacity mode but has no auto-scaling configured on either read or write capacity. The table has a fixed throughput ceiling — when traffic exceeds the provisioned limit, requests are throttled with ProvisionedThroughputExceededException. Auto-scaling adjusts capacity up and down based on actual utilization, preventing throttling during traffic spikes and reducing costs during quiet periods. A provisioned table without auto-scaling requires manual capacity adjustments and is prone to either over-provisioning (cost waste) or under-provisioning (throttling). This control gates on capacity_mode = PROVISIONED — PAY_PER_REQUEST tables have no capacity ceiling to scale.

**Remediation:** Enable auto-scaling for read and write capacity via the Application Auto Scaling API: aws application-autoscaling register-scalable-target --service-namespace dynamodb --resource-id table/TABLE --scalable-dimension dynamodb:table:ReadCapacityUnits --min-capacity 5 --max-capacity 1000. Or switch to on-demand mode (PAY_PER_REQUEST) to eliminate capacity management entirely.

---

### CTL.DYNAMODB.DAX.ALARM.CACHEHIT.001

**No CloudWatch Alarm for DAX Cache Hit Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the DAX CacheHitRate metric for the cluster. A low cache hit rate means most requests are cache misses — DAX forwards them to DynamoDB and the cluster is consuming resources (network, compute, memory) without providing the cache benefit it was sized for. A sudden hit rate drop may indicate cache flush, TTL expiration, key pattern change, or progressive cache failure (for example, a deleted DAX service role failing on each miss). Without an alarm, the degradation is invisible until DynamoDB capacity itself shows pressure.

**Remediation:** Create a CloudWatch alarm on the AWS/DAX CacheHitRate metric scoped to this cluster, threshold below the cluster's expected steady-state hit rate (typically 0.8 for read-heavy workloads), with SNS notification to the operations team. Sustained low hit rates warrant a review of the table's access pattern — DAX may not be the right tool for write-heavy or scan-heavy access.

---

### CTL.DYNAMODB.DAX.ALARM.ERRORS.001

**No CloudWatch Alarm for DAX Error Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch alarm monitors the DAX cluster's error metrics (ErrorRequestCount, FaultRequestCount, ConnectionErrors). DAX errors indicate cache-layer failures — connection errors, timeout errors, or internal DAX errors. If DAX is in the critical path, applications fail or degrade without notification. Combined with a deleted DAX service role (CTL.DYNAMODB.GHOST.DAXROLE.001), this blind spot is the difference between catching a progressive failure early and discovering it during a customer incident.

**Remediation:** Create CloudWatch alarms on the AWS/DAX ErrorRequestCount and FaultRequestCount metrics scoped to this cluster, threshold > 0 over a short evaluation window, with SNS notification to the operations team. Add a separate alarm on ClientConnectionCount dropping below the expected application baseline — that pattern catches DAX connectivity loss that the error metrics miss.

---

### CTL.DYNAMODB.DAX.ENCRYPT.REST.001

**DAX Cluster Not Encrypted at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

DAX cluster does not have encryption at rest enabled. DAX caches the most frequently accessed items from a DynamoDB table — customer records, session state, lookup tables — in memory and may overflow to disk. Without encryption at rest, the cached data, which is by definition the hottest data the application reads, is stored unencrypted in the DAX cluster's memory and any disk overflow. DAX encryption at rest is a cluster creation-time setting and cannot be enabled on an existing cluster — remediation requires creating a new cluster and migrating the application.

**Remediation:** Create a new DAX cluster with encryption at rest enabled (SSESpecification.Enabled=true on CreateCluster — choose a customer-managed KMS key for the strongest control). Migrate the application to the new cluster's endpoint, then delete the unencrypted cluster. Encryption cannot be enabled on an existing cluster, so a maintenance window is required.

---

### CTL.DYNAMODB.DAX.ENCRYPT.TRANSIT.001

**DAX Cluster Does Not Enforce TLS for Client Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

DAX cluster does not enforce TLS for connections from applications. DAX sits between every cached read/write and DynamoDB — every cache hit, every cache fill, every write- through traverses the connection between the application and the DAX cluster. Without TLS, all of this traffic is plaintext on the VPC network: cached item data (customer records, session tokens, application state), query parameters (partition keys and sort keys that may include user identifiers or business keys), and responses. Any process with network access to the DAX subnet can observe the traffic. TLS must be enabled at cluster creation; the cluster endpoint advertises whether it accepts TLS-only or accepts plaintext.

**Remediation:** Create a new DAX cluster with ClusterEndpointEncryptionType set to TLS, then update the application's DAX client to point at the TLS endpoint. Existing clients that connected to the plaintext endpoint will need to update their connection configuration to use TLS-aware DAX clients. Encryption-in-transit cannot be enabled on an existing cluster — recreation is required.

---

### CTL.DYNAMODB.DAX.ROLE.BROAD.001

**DAX Cluster IAM Role Has Excessive DynamoDB Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

DAX cluster's IAM service role has permissions beyond what's needed for the tables it caches — typically dynamodb:* on Resource: "*", or a wildcard table ARN. The DAX role's legitimate need is read access (GetItem, Query, Scan, BatchGetItem) and write-through access (PutItem, UpdateItem, DeleteItem, BatchWriteItem) on the specific tables being cached, scoped to those tables' ARNs. An overprivileged DAX role means the cache layer carries broader database access than the application it serves: a compromise of the DAX node (via SG misconfiguration, a runtime vulnerability, or a leaked credential) yields the role's full permission scope, not just the cached table.

**Remediation:** Replace the DAX role's policy with explicit actions (dynamodb:GetItem, Query, Scan, BatchGetItem, DescribeTable, plus PutItem/UpdateItem/DeleteItem if write-through is configured) scoped to the specific table ARN(s) the cluster caches. Avoid Resource: "*" on DynamoDB actions in this role.

---

### CTL.DYNAMODB.DAX.SG.BROAD.001

**DAX Cluster Security Group Allows Broad Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.4.2; soc2: CC6.6;

DAX cluster security group accepts inbound traffic from the entire VPC CIDR (10.0.0.0/8 and similar) or from 0.0.0.0/0 rather than restricting to specific application security groups or subnets. DAX is a database cache — its access surface should be narrow: only the application tier that actually needs cached database access. A broad SG opens the cache to every workload in the VPC, so any compromised resource (a developer-tools EC2 instance, an unrelated service, a runaway batch job) can read cached database contents and replicate the access patterns of the legitimate application.

**Remediation:** Replace broad CIDR rules with security-group references that name the application tier(s) that need DAX access. The SG rule should look like "from sg-app-tier on port 8111 (DAX), proto TCP" — not "from 10.0.0.0/8". For multi-tier applications with several legitimate consumers, list each consumer SG explicitly.

---

### CTL.DYNAMODB.DAX.SINGLENODE.001

**DAX Cluster Has Single Node**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; nist_800_53_r5: CP-10; soc2: A1.2;

DAX cluster has only one node — no replica, no failover. If the single node fails (instance failure, AZ outage, AWS maintenance), the cache disappears entirely and every request falls through to direct DynamoDB. For tables sized on the assumption that DAX absorbs most reads, the fall-through traffic can exceed the table's provisioned capacity and trigger throttling, cascading into application- visible latency or errors. A multi-node cluster (typically three nodes spread across AZs) preserves the cache through any single-node failure: one node loss reduces cache capacity but doesn't lose the cache entirely.

**Remediation:** Resize the cluster to at least three nodes spread across AZs (UpdateCluster --replication-factor=3 plus subnet group covering multiple AZs). For smaller workloads where cost matters, two nodes is the minimum that survives single-node failure. Verify the table's provisioned capacity (or on-demand mode) is sized for the worst-case scenario where DAX is gone — even with HA DAX, transient fallthrough during failover is normal.

---

### CTL.DYNAMODB.DELETEPROT.001

**DynamoDB Tables Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.1;

DynamoDB tables must have deletion protection enabled to prevent accidental or malicious table destruction. Without it, a single DeleteTable API call permanently destroys the table and all its data. AWS added DeletionProtectionEnabled in 2023 but no CIS benchmark or AWS-native framework checks it — the gap was discovered through cross-cloud transposition from Azure Cosmos DB purge protection. The same pattern as CTL.RDS.DELETEPROT.001 and CTL.NEPTUNE.DELETEPROT.001 but for the key-value store layer. Tables storing session state, feature flags, or application metadata are especially vulnerable — their loss causes immediate production impact with no recovery path unless PITR is also enabled.

**Remediation:** Enable deletion protection: aws dynamodb update-table --table-name <name> --deletion-protection-enabled. Pair with CTL.DYNAMODB.PITR.001 for defense-in-depth — deletion protection prevents table destruction, PITR enables recovery from data corruption.

---

### CTL.DYNAMODB.ENCRYPT.001

**DynamoDB Must Use Customer-Managed KMS Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; gdpr: Art.32; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

DynamoDB tables must use a customer-managed KMS key for encryption at rest. The default AWS-owned key does not support key revocation, audit of key usage, or cross-account key policies.

**Remediation:** Update the table encryption to use a customer-managed KMS key. Run: aws dynamodb update-table --table-name xxx --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=arn:...

---

### CTL.DYNAMODB.ENCRYPT.DAX.MISMATCH.001

**DynamoDB Table and DAX Cluster Encryption Posture Mismatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

DynamoDB table is paired with a DAX cluster, and the two layers have inconsistent encryption posture — typically the table is encrypted with a customer-managed KMS key while the DAX cache is not encrypted at rest, or vice versa. The most frequently accessed data lives in DAX. If DAX is unencrypted while the table is encrypted, the hottest rows have the weakest protection — operators who chose CMK at the table layer have implicitly accepted plaintext storage at the cache layer that fronts every read. The intent of the table- level encryption is undermined by the cache layer's looser posture. The control fires only on tables that have a DAX cluster (kind gate); tables with no DAX have no mismatch surface.

**Remediation:** Bring the DAX cluster's encryption posture in line with the table's: enable encryption at rest on DAX (cluster recreation required — see CTL.DYNAMODB.DAX.ENCRYPT.REST.001) so the cache layer matches or exceeds the table's protection. If the table's CMK choice was the wrong layer (rare), align in the other direction by relaxing the table — but this typically means the original CMK decision was unjustified rather than the DAX gap acceptable.

---

### CTL.DYNAMODB.EXPORT.UNENCRYPTED.001

**DynamoDB Export Targets Unencrypted S3 Bucket**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

DynamoDB table export is configured to write to an S3 bucket that does not use a customer-managed KMS key for default encryption. A DynamoDB export writes a full or partial copy of the table data — all items, all attributes — to S3 in DynamoDB JSON or Amazon Ion format. If the destination bucket uses SSE-S3 or no default encryption rather than SSE-KMS with a CMK, the export data is protected only by S3 bucket policies and IAM, without the key-policy control, audit, or revocation capability of a CMK. A table encrypted with CMK should export to a bucket with equivalent encryption — the export is the same data as the table, and weaker protection on the export undermines the CMK investment on the table.

**Remediation:** Configure the destination S3 bucket's default encryption to use SSE-KMS with a customer-managed key. Existing export files must be re-encrypted or deleted and re-exported. Update the bucket's default encryption via aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ARN"}}]}'.

---

### CTL.DYNAMODB.GHOST.DAXROLE.001

**DAX Cluster References Deleted IAM Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

DAX cluster's service role IAM ARN references a role that has been deleted. DAX uses this role for every DynamoDB call it makes — every cache miss, every cache fill, every write-through. With the role gone, DAX cannot perform DynamoDB operations and returns errors on every call. The failure mode is progressive rather than immediate: cache hits continue to work because the data is already in DAX memory, but cache misses fail with AccessDeniedException as DAX tries to read from DynamoDB using the deleted role. As cached items expire (TTL or eviction), the rate of cache misses rises, and the application's error rate rises with it. The progression goes from "occasional unexplained errors" to "everything fails" over the cache TTL window — minutes for short TTLs, hours for long ones.

**Remediation:** Re-create the role with the trust policy (dax.amazonaws.com) and the table-scoped DynamoDB permissions DAX needs (GetItem, Query, Scan, BatchGetItem plus PutItem/UpdateItem/DeleteItem if write-through is on). Or update the DAX cluster to reference an existing role with the same scope. Add a deletion guard on IAM roles that cross-references active DAX clusters before allowing the role to be deleted.

---

### CTL.DYNAMODB.GHOST.DAXSG.001

**DAX Cluster References Deleted Security Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

DAX cluster's network configuration references a security group that has been deleted. The cluster's network access rules are now undefined: AWS-side behavior on deleted SG references is to silently drop the SG from the effective rule set, so what looked like a tightly-scoped DAX configuration may now be effectively unrestricted (if no other SGs remain on the cluster) or effectively inaccessible (if the deleted SG was the only one allowing application traffic). Same ghost-reference pattern as the other SG ghosts in the catalog — CTL.RDS.GHOST.SG.001, CTL.EC2.LT.GHOST.SG.001, CTL.LAMBDA.GHOST.VPC.001 — applied to the DAX surface.

**Remediation:** Update the cluster's SG list to remove deleted SG IDs. Verify the remaining SGs still allow the application traffic the cluster needs (or add replacements if the deleted SG carried the only inbound rule). Add a deletion guard on security groups that cross-references active DAX clusters before allowing the SG to be deleted.

---

### CTL.DYNAMODB.GHOST.DAXSUBNET.001

**DAX Cluster References Deleted Subnet Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

DAX cluster's subnet group references one or more subnets that have been deleted from the VPC. DAX nodes placed in the deleted subnets cannot be replaced — if a node fails or AWS performs maintenance that requires node replacement, the new node has nowhere to go. Existing nodes continue to serve traffic until they need to be replaced; from that point, the cluster degrades. Multi-node clusters degrade gracefully (one node loss reduces capacity but doesn't empty the cache); single-node clusters fail entirely. The failure mode is identical to the other ghost-reference cases — config intact, target deleted, surface only on next replacement event.

**Remediation:** Update the subnet group to remove deleted subnet IDs and add replacement subnets in the same AZs as the deleted ones. If the original VPC layout was intentionally decommissioned, redeploy the DAX cluster into the new subnet topology rather than patching a stale subnet group. Add a deletion guard on subnets that cross-references active DAX clusters before allowing the subnet to be deleted.

---

### CTL.DYNAMODB.GLOBAL.ENCRYPT.MISMATCH.001

**Global Table Replicas Have Inconsistent Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

DynamoDB global table has replicas with different encryption configurations — the primary uses a customer-managed KMS key while one or more replicas use the AWS-owned key or a different CMK. Global table replication copies every item write to every replica. If the primary is CMK-encrypted and a replica is not, the same data has different protection levels across regions: the CMK-protected region has key-policy control, CloudTrail audit of every decrypt, and key revocation capability; the AWS-owned-key region has none of these. The weakest replica's encryption level is the effective encryption protection for the data set. Encryption settings must be consistent across all replicas.

**Remediation:** Update each replica's encryption to use the same CMK as the primary. Each replica must be updated independently via aws dynamodb update-table --table-name TABLE --replica-updates '[{"Update":{"RegionName":"REGION", "KMSMasterKeyId":"arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"}}]'. KMS keys are region-specific — the replica CMK must exist in the replica's region.

---

### CTL.DYNAMODB.GLOBAL.PITR.MISMATCH.001

**Global Table Replica Missing Point-in-Time Recovery**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); nist_800_53_r5: CP-9; pci_dss_v4.0: 10.7; soc2: A1.2;

DynamoDB global table has one or more replicas without point-in-time recovery enabled while the primary has PITR. PITR settings are per-region — enabling PITR on the primary does not propagate to replicas. If the replica region becomes the primary (failover) or is the region closest to the incident (replicated corruption or accidental bulk delete), the replica without PITR cannot be recovered within the 35-day window. PITR must be enabled on every replica independently.

**Remediation:** Enable PITR on each replica independently using aws dynamodb update-continuous-backups --table-name TABLE --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true executed in each replica's region. The default AWS region for the CLI must be set to the replica's region when running this command.

---

### CTL.DYNAMODB.GLOBAL.SINGLEREGION.001

**Global Table Has Only One Region**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

DynamoDB global table has replicas in only one region. A global table with a single region carries the overhead of global table infrastructure — service-linked role, mandatory DynamoDB Streams, and replication plumbing — without the geographic redundancy that justifies it. If the single region experiences an outage the table is unavailable, the same as a standard table. Either add replicas in additional regions to realise the DR benefit, or convert to a standard table to eliminate the overhead.

**Remediation:** Add at least one replica in another region with aws dynamodb create-global-table-replica --table-name TABLE --replica-updates '[{"Create":{"RegionName":"eu-west-1"}}]' Or remove the global table configuration and operate as a standard table if multi-region is not needed.

---

### CTL.DYNAMODB.GLOBAL.VERSION.001

**Global Table Uses Legacy 2017 Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC8.1;

DynamoDB global table uses the 2017.11.29 legacy version instead of the current 2019.11.21 version. Version 2017 has documented limitations: global secondary indexes lack eventual consistency guarantees across replicas, transactional writes (TransactWriteItems) are not supported, replication latency is higher than version 2019, and replica capacity must be managed independently per region rather than automatically. AWS recommends migrating all 2017 global tables to 2019. Migration cannot be done in-place — it requires recreating the table with 2019 global table configuration.

**Remediation:** Migrate to version 2019.11.21. This requires creating a new table with the same schema and global table configuration using the current API (which defaults to 2019), migrating data, and cutting over traffic. AWS provides a migration guide at https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables.tutorial.html

---

### CTL.DYNAMODB.GSI.UNUSED.001

**DynamoDB Global Secondary Index Has No Query Activity**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC8.1;

DynamoDB table has a global secondary index (GSI) with no query activity in 90+ days. Every write to the base table is replicated to each GSI — the GSI consumes write capacity proportional to the write throughput on the base table, and occupies storage proportional to the projected attributes and item count. A GSI with no queries incurs ongoing write and storage cost with no read benefit. Unused GSIs also increase write latency because each item write must be replicated to the index. This control flags GSIs that may be candidates for removal after confirming no active queries depend on them.

**Remediation:** Confirm no active application queries use the index (review CloudTrail data events for Query/Scan operations specifying the GSI name over the last 90 days). If the index is unused, delete it with aws dynamodb update-table --table-name TABLE --global-secondary-index-updates '[{"Delete":{"IndexName":"INDEX_NAME"}}]'. GSI deletion cannot be undone.

---

### CTL.DYNAMODB.INCOMPLETE.001

**Complete Data Required for DynamoDB Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required DynamoDB properties.

**Remediation:** Ensure the extractor calls aws dynamodb describe-table and maps the SSEDescription to the database.encryption observation properties.

---

### CTL.DYNAMODB.INSIGHTS.001

**DynamoDB Contributor Insights Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

DynamoDB Contributor Insights is not enabled for the table. Contributor Insights provides real-time identification of the most accessed and most throttled partition keys. Without it, hot key analysis requires enabling CloudTrail data events (high volume, high cost) and correlating raw logs by partition key. Hot keys are the most common cause of partition-level throttling that auto-scaling cannot fix — auto-scaling adjusts table capacity, not partition capacity.

**Remediation:** Enable Contributor Insights on the table: aws dynamodb update-contributor-insights --table-name xxx --contributor-insights-action ENABLE. Repeat for each global secondary index that carries significant traffic. Review the resulting reports weekly to identify hot partitions and adjust the schema (write sharding, distributed counters) before throttling materializes.

---

### CTL.DYNAMODB.LIFECYCLE.DORMANT.001

**DynamoDB Table Has No Activity in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

DynamoDB table has had no read or write activity (zero ConsumedReadCapacityUnits and ConsumedWriteCapacityUnits) for more than 90 days. The table retains its full configuration: data, IAM access policies, stream configuration, global replicas, and backup schedules. Nobody monitors a dormant table for anomalous access — it is assumed unused. But the IAM policies still grant access, and the data is readable by any principal with dynamodb:GetItem, Query, or Scan on the table. Dormant tables with customer data, historical records, PII, or credentials are a latent data exposure surface that combines inaccessible-looking status with fully-accessible data. 90-day threshold matches Lambda, IAM role, and EC2 dormant controls for consistency.

**Remediation:** Review whether the table is still needed. If data can be archived, export to S3 and delete the table. If data must be retained but is no longer actively queried, disable any active streams, remove direct IAM grants, and restrict access to a break-glass role. Tag the table with the retention reason and review date. Use aws cloudwatch get-metric-statistics to confirm zero ConsumedReadCapacityUnits and ConsumedWriteCapacityUnits over the last 90 days.

---

### CTL.DYNAMODB.LIFECYCLE.STREAM.ORPHAN.001

**DynamoDB Stream Consumer Lambda Has Been Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

DynamoDB Stream is enabled and a Lambda event source mapping (ESM) is configured, but the target Lambda function has been deleted. The stream produces a record for every item modification — creates, updates, deletes. The ESM is active. The Lambda function does not exist. Records are produced, never consumed, and expire after 24 hours unprocessed. If the stream consumer performed critical operations — event-driven replication to another system, audit pipeline, materialized view maintenance, notification dispatch — those operations silently stopped when the function was deleted. The stream appears configured and the ESM appears active; nothing surfaces the failure until downstream systems show stale data or missing notifications. Complementary to CTL.LAMBDA.TRIGGER.GHOST.001 (Lambda ESM referencing a deleted stream) — this control detects the inverse: stream exists, ESM exists, function deleted.

**Remediation:** Either re-create the Lambda function and update the event source mapping, or remove the orphaned ESM using aws lambda delete-event-source-mapping --uuid ESM_UUID and disable the stream if it is no longer needed (aws dynamodb update-table --stream-specification StreamEnabled=false). Check whether downstream systems that depended on stream processing are receiving stale data.

---

### CTL.DYNAMODB.PITR.001

**Point-in-Time Recovery Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); nist_800_53_r5: CP-9; soc2: A1.1;

DynamoDB tables must have point-in-time recovery (PITR) enabled. Without PITR, accidental deletes, application bugs, or ransomware that corrupts table data cannot be recovered. PITR provides continuous backups with per-second granularity for the last 35 days.

**Remediation:** Enable PITR using aws dynamodb update-continuous-backups --table-name TABLE --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true.

---

### CTL.DYNAMODB.STREAM.MAXEXPOSURE.001

**DynamoDB Stream Exposes Full Item History**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.1;

DynamoDB Stream is configured with StreamViewType NEW_AND_OLD_IMAGES — every stream record includes both the complete previous state and the complete current state of the modified item. This is the maximum data exposure the stream can produce: a single update exposes all attributes before and after the change. Stream consumers — Lambda event source mappings, Kinesis Data Streams — have access to the full change history for every item in the table. If a consumer is overprivileged, cross-account, or compromised, it can reconstruct the complete modification history of every item. NEW_AND_OLD_IMAGES is appropriate when the consumer genuinely needs both states (audit trail, CDC replication). Verify the consumer's actual requirement before accepting this configuration.

**Remediation:** If the consumer does not need the old item state, reduce to NEW_IMAGE (current state only) or KEYS_ONLY (partition and sort keys only). Update via aws dynamodb update-table --table-name TABLE --stream-specification StreamEnabled=true, StreamViewType=NEW_IMAGE. Note that changing the stream view type creates a new stream — consumers must be updated to the new stream ARN.

---

### CTL.DYNAMODB.STREAM.NOCONSUMER.001

**DynamoDB Stream Has No Consumer**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-11; soc2: CC6.1;

DynamoDB Stream is enabled but no consumer is configured — no Lambda event source mapping and no Kinesis Data Streams shard-level consumer. Stream records are written for every item modification, accumulate for 24 hours, and then expire unprocessed. The stream is consuming DynamoDB capacity (stream reads are billed) and retaining a 24-hour window of change records that nobody processes. An unconsumed stream with NEW_AND_OLD_IMAGES or NEW_IMAGE view type is a data retention concern: change data for every item modification persists for 24 hours accessible to any principal with dynamodb:GetShardIterator and dynamodb:GetRecords on the stream ARN, regardless of application intent.

**Remediation:** Either configure a consumer for the stream (Lambda event source mapping via aws lambda create-event-source-mapping --event-source-arn STREAM_ARN --function-name FUNCTION) or disable the stream if it is not needed (aws dynamodb update-table --table-name TABLE --stream-specification StreamEnabled=false).

---

### CTL.DYNAMODB.TTL.MISSING.001

**DynamoDB Temporal Table Has No TTL Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(c)(2); nist_800_53_r5: SI-12; soc2: CC6.1;

DynamoDB table stores temporal data (sessions, tokens, temporary records, or cache entries — identified by table name patterns or tags) but does not have TTL enabled. Without TTL, expired items accumulate indefinitely: consuming provisioned capacity or increasing on-demand costs, growing scan and backup sizes, and retaining data beyond its intended lifetime. For tables containing PII or PHI, missing TTL may violate data minimization requirements that mandate deletion after a specified period. TTL provides automatic, item-level expiration based on a timestamp attribute with no application code required, no additional cost, and eventual deletion that happens within 48 hours of expiry time. This control gates on has_temporal_tags to avoid false positives on tables where TTL does not apply (configuration tables, reference data).

**Remediation:** Designate a timestamp attribute in item data (epoch seconds in the future representing the expiry time). Enable TTL on the table using aws dynamodb update-time-to-live --table-name TABLE --time-to-live-specification Enabled=true,AttributeName=expires_at. DynamoDB will delete items within 48 hours after their TTL attribute timestamp passes.

---

### CTL.DYNAMODB.VPC.ENDPOINT.001

**VPC Must Have DynamoDB Gateway Endpoint**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7;

VPCs accessing DynamoDB should have a gateway endpoint.

**Remediation:** Create a DynamoDB gateway endpoint.

---


# Control Reference — OPENSEARCH

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.OPENSEARCH.ACCESS.POLICY.001

**Access Policy Must Not Allow Wildcard Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

OpenSearch domain access policies must not grant access to wildcard principals (Principal: *). A wildcard principal in the resource-based policy allows any AWS account or unauthenticated user to access the cluster, depending on whether the domain is public or VPC-only. Combined with a public endpoint, this enables completely anonymous access.

**Remediation:** Replace wildcard principals with specific IAM role ARNs or account IDs. Use condition keys (aws:SourceIp, aws:SourceVpc) to further restrict access.

---

### CTL.OPENSEARCH.ALARM.5XX.001

**OpenSearch 5xx HTTP Errors Have No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on HTTP 5xx error rate (`5xx` metric). 5xx surge indicates internal cluster errors — query parser failures, JVM out-of-memory, plugin crashes — and is the most direct user-impact signal. Without an alarm, error spikes appear in dashboards but do not page anyone.

**Remediation:** Alarm: 5xx > 1% of total request volume for 5min sustained (page). Pair with 4xx alarm for client-side errors.

---

### CTL.OPENSEARCH.ALARM.AUTOSNAPSHOT.FAILURE.001

**OpenSearch Automated Snapshot Failure Has No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16, A.8.13; nist_800_53_r5: AU-12, CP-9; soc2: CC7.2, A1.2;

OpenSearch domain has no CloudWatch alarm on the `AutomatedSnapshotFailure` metric. A run of failed automated snapshots silently degrades the recovery position; by the time on-call is paged for an incident, the available snapshot may be days old. Discovered too late, this is a data-loss-magnifying defect.

**Remediation:** Alarm: AutomatedSnapshotFailure >= 1 for 1 datapoint (page). Investigate KMS key accessibility, S3 bucket health, repository role trust.

---

### CTL.OPENSEARCH.ALARM.CLUSTER.RED.001

**OpenSearch Cluster Red Status Has No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on the `ClusterStatus.red` metric. ClusterStatus.red means at least one primary shard is unassigned; data is unavailable for queries on that shard. Without an alarm, the cluster sits red until a customer or downstream pipeline complains.

**Remediation:** Create CloudWatch alarm: metric ClusterStatus.red >= 1 for 1 datapoint, page on-call. Recover-action: AutomatedSnapshot restore or shard reallocation.

---

### CTL.OPENSEARCH.ALARM.CLUSTER.YELLOW.001

**OpenSearch Cluster Yellow Status Has No CloudWatch Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on the `ClusterStatus.yellow` metric. Yellow means replicas unassigned (data still queryable from primaries, but resilience reduced). A persistent yellow state usually precedes red by hours; an alarm gives operators time to react before data unavailability.

**Remediation:** Create CloudWatch alarm: ClusterStatus.yellow >= 1 sustained for 15 minutes, route to operations channel.

---

### CTL.OPENSEARCH.ALARM.FREESTORAGE.001

**OpenSearch Free Storage Space Has No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on the `FreeStorageSpace` metric. Once FreeStorageSpace drops below the cluster's flood-stage watermark (default 95% utilization), OpenSearch sets indices read-only and writes fail. Recovery requires manual intervention and is slow.

**Remediation:** Alarm: FreeStorageSpace < 25% of one-node capacity sustained 15min (warn). Page at < 10%. Pair with auto-scaling or storage expansion plan.

---

### CTL.OPENSEARCH.ALARM.JVM.PRESSURE.001

**OpenSearch JVM Memory Pressure Has No CloudWatch Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on the `JVMMemoryPressure` metric (data nodes). Sustained JVM pressure > 85% causes long GC pauses, search timeouts, and indexer rejects. Master pressure (handled separately) stalls cluster state; data pressure stalls user workload.

**Remediation:** Alarm: JVMMemoryPressure > 85% sustained 15min (warn), > 92% (page). Investigate via CloudWatch Container Insights / hot-thread API.

---

### CTL.OPENSEARCH.ALARM.KMS.INACCESSIBLE.001

**OpenSearch KMS Key Access Has No CloudWatch Alarm**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16, A.8.24; nist_800_53_r5: AU-12, SC-12; soc2: CC7.2, A1.2;

OpenSearch domain has no CloudWatch alarm on `KMSKeyError` or `KMSKeyInaccessible` metrics. When the at-rest encryption KMS key becomes unreachable (key disabled, policy change, cross-account grant revoked), the domain cannot decrypt indices — search and indexing fail until access is restored. Without an alarm, on-call is paged by customer impact rather than the cause.

**Remediation:** Alarms: KMSKeyError >= 1 (page), KMSKeyInaccessible >= 1 (page). On fire, check key state, key policy, key grants in cross-account scenarios.

---

### CTL.OPENSEARCH.ALARM.MASTER.HEALTH.001

**OpenSearch Master Node Health Has No CloudWatch Alarms**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarms on master-node health metrics: `MasterReachableFromNode`, `MasterCPUUtilization`, or `MasterJVMMemoryPressure`. The master node drives shard allocation, cluster-state propagation, and routing — degradation here manifests as cluster-wide stalls. The set is foundational for any production-tier domain.

**Remediation:** Create alarms: MasterReachableFromNode < 1 (page), MasterCPUUtilization > 80% sustained 15min (warn), MasterJVMMemoryPressure > 85% (page).

---

### CTL.OPENSEARCH.ALARM.NODES.001

**OpenSearch Node Count Drop Has No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarm on the `Nodes` metric. Silent node loss reduces capacity and resilience; without an alarm, on-call learns about it from downstream capacity / latency degradation. Particularly important for clusters with dedicated masters where the loss of a master is immediately service-impacting.

**Remediation:** CloudWatch alarm: Nodes < expected for 1 datapoint, page on-call.

---

### CTL.OPENSEARCH.ALARM.THREADPOOL.001

**OpenSearch Threadpool Saturation Has No CloudWatch Alarms**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

OpenSearch domain has no CloudWatch alarms on threadpool saturation metrics: `ThreadpoolSearchQueue`, `ThreadpoolWriteQueue`, or `ThreadpoolSearchRejected`. Threadpool saturation precedes user-visible latency or rejects; without alarms, the cluster appears to slow down for no traceable reason.

**Remediation:** Alarms: ThreadpoolSearchQueue > 100 (warn), ThreadpoolWriteQueue > 50 (warn), ThreadpoolSearchRejected > 0 (page).

---

### CTL.OPENSEARCH.AOSS.ACCESS.WILDCARD.001

**OpenSearch Serverless Data-Access Policy Uses Wildcard Principal Or Action**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

OpenSearch Serverless collection's data-access policy uses `Principal: "*"`, grants `aoss:*` cluster-wide, or grants delete-class actions (e.g., `aoss:DeleteCollectionItems`) to a read-tier role. Each variant produces an effective access surface much wider than the policy review suggests.

**Remediation:** Replace Principal: "*" with specific IAM ARNs. Replace aoss:* with explicit action list. Move delete actions to a separate write-tier policy.

---

### CTL.OPENSEARCH.AOSS.CAPACITY.MISSING.001

**OpenSearch Serverless Capacity Or Lifecycle Policy Missing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.30; nist_800_53_r5: CM-2, CP-2; soc2: CC8.1;

OpenSearch Serverless collection has no capacity policy (max_indexing / max_search capacity uncapped) or no lifecycle policy (collection grows unboundedly). AOSS bills by consumed OCU (OpenSearch Compute Units); uncapped capacity = uncapped bill. Lifecycle policies trim old data; without one, all data ages forever.

**Remediation:** Create capacity policy via aoss: UpdateAccountSettings with maxIndexingCapacity and maxSearchCapacity. Create lifecycle policy via aoss:CreateLifecyclePolicy.

---

### CTL.OPENSEARCH.AOSS.ENCRYPT.AWS.OWNED.001

**OpenSearch Serverless Collection Uses AWS-Owned Encryption Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

OpenSearch Serverless collection's encryption policy uses an AWS-owned key (default) rather than a customer-managed KMS key. AWS-owned keys are not auditable, can't be selectively revoked, and can't be rotated under customer schedule. For regulated workloads (HIPAA, PCI, SOC2), customer-managed keys are required.

**Remediation:** Create encryption policy with KmsARN pointing to a customer-managed key. Apply at collection creation; cannot be changed in-place.

---

### CTL.OPENSEARCH.AOSS.ENCRYPT.POLICY.MISSING.001

**OpenSearch Serverless Encryption Policy Not Attached At Collection Create**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, CM-3; soc2: CC6.7, CC8.1;

OpenSearch Serverless collection was created without an explicit encryption policy attached before creation. AOSS applies a default AWS-owned encryption silently; the collection inventory lists encryption as enabled but key custody is AWS-owned. Encryption policy must be created before the collection.

**Remediation:** Recreate the collection with explicit encryption policy. If the collection holds data, snapshot first; create new collection with proper encryption; restore.

---

### CTL.OPENSEARCH.AOSS.NETPOLICY.PUBLIC.001

**OpenSearch Serverless Collection Network Policy Permits Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch Serverless collection's network policy permits `Public` access type, or has no network policy attached (default-public), or permits `Public` and `VPC` simultaneously (VPC pretense). Collection is reachable from the internet despite "VPC-only" appearance in the inventory. AOSS network policies are the only network-level filter on collections.

**Remediation:** Update network policy to specify VPC-only via aoss:CreateSecurityPolicy with AccessType=VPC and explicit VPCe ID list. Verify with GetSecurityPolicy.

---

### CTL.OPENSEARCH.AOSS.VPCE.MISSING.001

**OpenSearch Serverless VPC Endpoint Missing While VPC-Only Network Policy Set**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: CM-2, SC-7; soc2: CC8.1, CC6.1;

OpenSearch Serverless collection has a network policy declaring `VPC` access type but no AOSS VPC endpoint exists in the consumer VPC. Clients in the consumer VPC cannot reach the collection; the policy's intent is not implemented end-to-end. Common after policy was applied speculatively without follow- through.

**Remediation:** Create AOSS VPC endpoint in the consumer VPC via aoss:CreateVpcEndpoint. Verify network policy references the endpoint ID.

---

### CTL.OPENSEARCH.AUDIT.CATEGORIES.INCOMPLETE.001

**OpenSearch Audit Log Categories Missing FAILED_LOGIN Or AUTHENTICATED**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.15; nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2.1, 10.2.2; soc2: CC7.2, CC7.3;

OpenSearch FGAC audit log is enabled but the enabled categories do not include `FAILED_LOGIN` and `AUTHENTICATED`. Without FAILED_LOGIN, password-spraying / credential-stuffing campaigns generate no signal in audit. AUTHENTICATED bounds the timeline of who logged in. Both are required for any meaningful intrusion-detection workflow on the cluster.

**Remediation:** Update audit_log_categories to include at minimum: FAILED_LOGIN, AUTHENTICATED, GRANTED_PRIVILEGES, MISSING_PRIVILEGES, INDEX_EVENT.

---

### CTL.OPENSEARCH.AUDIT.LOG.001

**OpenSearch Domains Must Have Audit Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: Opensearch.6; mitre_attack: T1213; nist_800_53_r5: AU-12;

OpenSearch audit logs record all requests to the domain including queries, index operations, and authentication events. Without audit logging, an attacker who accesses the domain can search, read, and export data without any record of what was accessed. OpenSearch domains often contain aggregated application logs, business data, and user activity — making them high-value collection targets.

**Remediation:** Enable audit logs on the domain. Audit logs require fine-grained access control to be enabled first. Update the domain configuration to publish audit logs to CloudWatch Logs.

---

### CTL.OPENSEARCH.AUDIT.LOGGROUP.MISSING.001

**OpenSearch Audit Log Destination Configured But CloudWatch Group Missing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15; nist_800_53_r5: AU-3, AU-12; pci_dss_v4.0: 10.4.1; soc2: CC7.2, A1.2;

OpenSearch domain audit log destination references a CloudWatch Log group that does not exist. Audit log delivery silently drops events — the domain reports audit-enabled, the log pipeline appears healthy from inventory, but no events arrive at any consumer. Common pattern: log group renamed / deleted by another team without checking which services delivered to it.

**Remediation:** Re-create the log group or repoint audit delivery to an existing group via UpdateDomainConfig --log-publishing-options. Verify with describe-domain-config + log group list.

---

### CTL.OPENSEARCH.AUDIT.NOBODY.CAPTURE.001

**OpenSearch Audit Log Body Capture Disabled For Search Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15; nist_800_53_r5: AU-3, AU-12; pci_dss_v4.0: 10.2.5; soc2: CC7.2;

OpenSearch audit log body capture is disabled. REQUEST events show that a search ran, but the query body — `_source` filters, aggregations, or DSL clauses — is not in the audit record. Without the body, "did the attacker exfiltrate PII?" is unanswerable from audit alone. Trade-off: body-capture increases audit log volume / cost, but is required for any meaningful exfil-grade investigation.

**Remediation:** Enable audit_log_request_body for HTTP REST requests. Decide whether to apply cluster-wide or per-index (FGAC supports per-role body capture). Increase log group retention budget; bodies are larger than headers.

---

### CTL.OPENSEARCH.AUDIT.NOINDEX.NAME.001

**OpenSearch Audit REQUEST Events Do Not Capture Index Name**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15; nist_800_53_r5: AU-3, AU-12; pci_dss_v4.0: 10.2.4; soc2: CC7.2;

OpenSearch audit log REQUEST events are configured to omit the target index name. Audit events show "user X ran a search" but not "on index Y." During incident review, attribution to specific tenants / data classes is impossible without the index name. The `audit_log_resolve_indices` setting is required for index-aware audit.

**Remediation:** Set audit_log_resolve_indices: true in the FGAC audit config. Verify with sample REQUEST event in CloudWatch — the resolved_indices field should be present.

---

### CTL.OPENSEARCH.AUDIT.RETENTION.SHORT.001

**OpenSearch Audit Log Retention Below Compliance Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.530(j); iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

OpenSearch audit log destination CloudWatch group has retention shorter than the org's regulatory minimum (HIPAA 6 years, PCI-DSS 1 year, SOX 7 years, common generic minimum 13 months). For HIPAA / PCI / SOC2 -scoped domains, audit logs that age out before the regulatory window create a compliance failure regardless of how thoroughly they were collected.

**Remediation:** Update retention to match compliance scope:
  aws logs put-retention-policy
    --log-group-name /aws/opensearch/<domain>
    --retention-in-days 2557
HIPAA: 2557 (7y); PCI: 365; SOC2: 365 min. Pair with S3 archival for long retention.

---

### CTL.OPENSEARCH.AUDIT.SECURITY.CHANGES.SHARED.001

**OpenSearch Security-Plugin Changes Share Retention With Operational Logs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.33, A.8.34; nist_800_53_r5: AU-11, CM-3; pci_dss_v4.0: 10.5.1; soc2: CC7.2, CC8.1;

OpenSearch security-plugin changes (FGAC role edits, internal-user mutations, role-mapping updates) are written to the same CloudWatch Log group as operational audit events with shared retention. High-volume operational events push security-changes events out of retention before the regulatory window for security-event preservation closes. Security- changes need their own retention bucket.

**Remediation:** Configure separate CloudWatch destination for security-changes events (or use a metric filter to copy them to a longer-retention group). Apply 7y retention for security- changes if SOX-scoped, 6y if HIPAA-scoped.

---

### CTL.OPENSEARCH.AUTH.001

**Authentication Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.5; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

OpenSearch domains must have authentication enabled. A domain without authentication allows anyone with network access to query, index, delete, and enumerate all data. The Darkbeam breach (2023) exposed 3.8 billion credentials because the Elasticsearch cluster required zero authentication. The Wyze breach (2019) exposed 2.4 million user records via the same pattern. Authentication is the single most critical OpenSearch security control.

**Remediation:** Enable fine-grained access control with an internal user database or IAM authentication. At minimum, enable the security plugin with a master user. For production, use IAM-based authentication via SAML or Cognito for OpenSearch Dashboards.

---

### CTL.OPENSEARCH.AUTH.BASIC.OVER.FGAC.001

**OpenSearch HTTP Basic Auth Layered In Front Of FGAC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-5, AU-3; pci_dss_v4.0: 8.2.2, 8.3.1; soc2: CC6.1, CC6.6;

OpenSearch domain has fine-grained access control (FGAC) enabled, but clients are configured to authenticate via HTTP Basic auth in front of FGAC's identity model. The Basic-auth credential maps to a single FGAC user, and that user effectively becomes a shared service account for all callers behind the Basic credential. Per-call identity is lost; FGAC role mappings, audit logs, and DLS/FLS attribution all collapse to one identity.

**Remediation:** Replace shared Basic credential with per-service IAM role + IRSA (Kubernetes) or IAM role assumption. Each caller authenticates with its own identity; FGAC sees the actual role / user; audit attribution works.

---

### CTL.OPENSEARCH.AUTOTUNE.OFF.001

**OpenSearch Auto-Tune Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1;

OpenSearch domain has Auto-Tune disabled. Auto-Tune adjusts JVM heap, garbage collector, and queue sizes based on observed workload. Without it, recommended settings drift over time as workload changes; manual tuning is rarely revisited. Auto-Tune applies during maintenance window.

**Remediation:** Enable via UpdateDomainConfig --auto-tune- options DesiredState=ENABLED. Pair with off-peak maintenance window.

---

### CTL.OPENSEARCH.AZ.NOSTANDBY.001

**OpenSearch Multi-AZ With Standby Available But Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.14; nist_800_53_r5: CP-7; soc2: A1.1, A1.2;

OpenSearch multi-AZ domain has the `with_standby` option available (engine version >= 1.3 / 2.x) but disabled. With standby, one AZ is reserved for failover only — faster recovery (sub-minute) and SLA-eligible. Without standby, multi-AZ failover takes several minutes during which writes fail and reads degrade.

**Remediation:** Enable via UpdateDomainConfig --cluster-config multi_az_with_standby_enabled=true. Capacity increase: 1 AZ worth of nodes for standby.

---

### CTL.OPENSEARCH.AZ.SINGLE.001

**OpenSearch Production Domain Deployed In Single AZ**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.14; nist_800_53_r5: CP-7, SC-5; soc2: A1.1, A1.2;

OpenSearch production-tier domain has fewer than 2 Availability Zones, or has multi-AZ enabled but only one data node per AZ. AZ- failure event takes the cluster offline; with one node per AZ, partial-zone events impact search capacity. Multi-AZ with multiple data nodes per zone is the production baseline.

**Remediation:** Migrate via blue-green to multi-AZ with minimum 2 data nodes per AZ. Use `with_standby` for fastest failover.

---

### CTL.OPENSEARCH.BLUEGREEN.STUCK.001

**OpenSearch Blue-Green Deployment Failed Without Rollback**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1, A1.2;

OpenSearch domain has a blue-green deployment in `Failed` state for more than 24 hours without rollback. Cluster runs in a partial state; old config still active but new config state-machine is stuck. Operators commonly ignore the failure because the domain appears healthy.

**Remediation:** Inspect via DescribeDomainChangeProgress. Either retry or call CancelDomainChange to roll back. Investigate root cause via domain config events / CloudTrail.

---

### CTL.OPENSEARCH.CCR.SECURITY.INDEX.001

**OpenSearch CCR Replicates Security Plugin Index Across Clusters**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, IA-5; pci_dss_v4.0: 8.3.1; soc2: CC6.1, CC6.3;

OpenSearch CCR auto-follow pattern matches the `.opendistro_security` security index, replicating FGAC users / role mappings from the leader cluster to the follower. Different clusters need different identity state; cross-replicating it imports stale identities, breaks per-cluster role mappings, and can expose hashed credentials cross-domain.

**Remediation:** Update CCR auto-follow pattern to exclude `.opendistro_security*`. Each cluster manages its own identity state.

---

### CTL.OPENSEARCH.CCS.COMPLIANCE.BOUNDARY.001

**OpenSearch Cross-Cluster Connection Crosses Compliance Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4; hipaa: 164.502(e); iso_27001_2022: A.5.10, A.8.20; nist_800_53_r5: AC-3, AC-4; pci_dss_v4.0: 1.3.4; soc2: CC6.1, CC8.1;

OpenSearch CCS / CCR connection between two domains crosses a compliance scope boundary: PII / PHI / PCI-scoped data accessed from a non-scoped cluster, GDPR-EU index queryable from a US cluster, etc. Compliance requires the data to remain within scope; cross-cluster query / replication breaches it.

**Remediation:** Tear down the cross-cluster connection. Implement compliance-scoped clusters that do not federate. If federation is required, restrict to non-regulated indices via explicit pattern allowlist.

---

### CTL.OPENSEARCH.CCS.NOTLSVERIFY.001

**OpenSearch Cross-Cluster Connection Skips TLS Verification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-8; iso_27001_2022: A.8.24; nist_800_53_r5: SC-8, SC-12; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch cross-cluster connection between two domains is configured to skip TLS certificate verification, or runs unencrypted. Either permits MITM on the cross-cluster path; the remote cluster's identity is not authenticated. Common during initial setup with self-signed certs that operators "temporarily" disable verification for and never re-enable.

**Remediation:** Re-enable TLS verification; use ACM-issued certs on both sides; encrypt CCR/CCS in-transit.

---

### CTL.OPENSEARCH.CCS.PUBLIC.001

**OpenSearch Cross-Cluster Connection Traverses Public Endpoint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7, SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch cross-cluster search (CCS) or cross- cluster replication (CCR) connection between two domains traverses the public internet endpoint of either side rather than VPC PrivateLink. Search / replication traffic contains the data being queried; transiting the public path exposes it to interception and inflates egress cost.

**Remediation:** Migrate cross-cluster connection to use VPC PrivateLink endpoints on both ends.

---

### CTL.OPENSEARCH.CCS.SHADOW.001

**OpenSearch Cross-Cluster Connection Not In Inventory**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.5.16; nist_800_53_r5: CM-8, CA-7; soc2: CC8.1, CC6.1;

OpenSearch domain has cross-cluster connections (CCS or CCR) that are not tracked in the organization's inventory / IaC. Shadow trust: source / target cluster setup happened during an integration push, was never captured, and now is outside review. Periodic cross-cluster trust audit misses these entirely.

**Remediation:** Inventory all cross-cluster connections via DescribeOutboundConnections / DescribeInboundConnections. Reconcile against IaC source. Document each connection with owner / purpose / sunset date.

---

### CTL.OPENSEARCH.CCS.UNSCOPED.001

**OpenSearch Cross-Cluster Trust Or Replication Pattern Unscoped**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.3;

OpenSearch cross-cluster setup is over-broad: CCS trust granted to a non-production source cluster, CCS access policy not index-scoped, or CCR auto-follow pattern matches `*` (replicates everything). Each variant exposes more data than the integration requires.

**Remediation:** Restrict CCS to production-tier source clusters only; scope access policy by index pattern; restrict CCR auto-follow to specific index prefixes.

---

### CTL.OPENSEARCH.CROSSREGION.ENCRYPT.MISMATCH.001

**Cross-Cluster Replication Has Inconsistent Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

OpenSearch domain with cross-cluster replication has follower indices in regions with different encryption configurations than the leader. If the leader uses a customer-managed KMS key and a follower does not, the same data has different protection levels across regions. The weakest follower's encryption level is the effective protection for the replicated data set.

**Remediation:** Recreate follower domains with the same CMK tier as the leader. Each region's key must exist in that region. Update cross-cluster replication connections after recreating the follower.

---

### CTL.OPENSEARCH.CUSTOM.CERT.EXPIRY.001

**OpenSearch Custom Endpoint Certificate Near Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12, SC-17; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-17; owasp_nhi: NHI7; soc2: CC7.4, A1.2;

OpenSearch domain custom endpoint TLS certificate expires within 30 days and no automated rotation is configured. ACM-issued certs auto-renew if the CNAME validation record is in place; certs imported from external sources do not. Once a cert expires, every TLS handshake fails: the domain is reachable but unusable for any TLS-verifying client. Outage scope is every client that talks to the custom endpoint.

**Remediation:** Migrate to ACM-managed cert with DNS validation so AWS auto-renews. For imported certs, set up a CloudWatch / EventBridge alert on AcmCertificateExpiration metric and rotate before expiry. Verify the domain config picks up the new cert via UpdateDomainConfig --domain-endpoint-options.

---

### CTL.OPENSEARCH.CUSTOM.CERT.UNTRUSTED.001

**OpenSearch Custom Endpoint Certificate From Untrusted CA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-8, SC-13; iso_27001_2022: A.8.24; nist_800_53_r5: SC-8, SC-12, SC-13; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch domain has a custom endpoint configured with an ACM certificate issued by a private / internal / untrusted CA whose root is not in the client trust store. Clients connecting to the custom endpoint either fail TLS verification or (worse) operators globally disable verification to make the connection work, eliminating any value TLS provides.

**Remediation:** Replace with a certificate from a public CA issued via ACM (free for AWS-managed services). Or distribute the private CA root to all clients that consume the custom endpoint and document the trust path. Verify with:
  openssl s_client -connect <custom-endpoint>:443
    -servername <custom-endpoint>

---

### CTL.OPENSEARCH.CUSTOM.ENDPOINT.PUBLIC.001

**OpenSearch Custom Endpoint Targets Public Domain When VPC Available**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch domain has a custom endpoint (CNAME) that resolves to the public domain endpoint while a VPC endpoint is also available. The custom endpoint is the one published to clients; using the public endpoint behind it bypasses the VPC isolation that the VPC endpoint was provisioned to provide. Operators commonly add a custom endpoint for branding without realizing it pins traffic to the public path.

**Remediation:** Repoint the custom endpoint CNAME to the VPC endpoint. Disable the public endpoint via UpdateDomainConfig, or update the access policy to deny non-VPC source IPs. Verify with:
  dig +short <custom-endpoint>
The result should resolve to the VPC-internal address, not the public one.

---

### CTL.OPENSEARCH.DATA.NODE.SINGLE.001

**OpenSearch Production Domain Has Single Data Node**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.14; nist_800_53_r5: CP-7, SC-5; soc2: A1.1, A1.2;

OpenSearch production-tier domain has only one data node. Any node-level event (instance retirement, kernel upgrade, EBS detach) takes the cluster offline. Single-data-node setups are appropriate only for development / ephemeral workloads.

**Remediation:** Scale to >= 3 data nodes; pair with >= 1 replica setting on indices to distribute data.

---

### CTL.OPENSEARCH.DEFAULT.ADMIN.PRESENT.001

**OpenSearch Default admin User Not Removed After Master Setup**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, AC-2; pci_dss_v4.0: 2.2, 8.2.1; soc2: CC6.1;

OpenSearch domain's internal user database still contains the default `admin` user after the FGAC master setup completed. The default user is documented, has well-known capabilities, and is a primary target for credential-stuffing / default-password attacks. Once the operational master user is in place, the default admin should be removed.

**Remediation:** Delete the default admin user via Dashboards Security plugin or opensearch-cli. Confirm via _security/api/internalusers — admin should not appear.

---

### CTL.OPENSEARCH.DELETE.NOSNAPSHOT.001

**OpenSearch Domain Deletion Not Gated By Pre-Delete Snapshot**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13; nist_800_53_r5: CP-9, CM-3; soc2: CC7.4, A1.2;

OpenSearch domain deletion process / IAM doesn't enforce a pre-delete manual snapshot. Default `DeleteDomain` API removes the domain immediately; automated snapshots are gone with the domain. Recovery from accidental deletion is impossible unless a manual snapshot was taken first. CI/CD or break-glass processes must enforce snapshot-before-delete.

**Remediation:** Add IAC / CI/CD step: take manual snapshot + verify in S3 + only then call DeleteDomain. Or use SCP that denies DeleteDomain unless tag "deletion_protection": "false" is set, forcing operator to pre-arm.

---

### CTL.OPENSEARCH.DELETION.PROTECTION.OFF.001

**OpenSearch Production Domain Has No Deletion Protection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-3, CP-9; soc2: CC8.1, A1.2;

OpenSearch production-tier domain has no termination protection. A single DeleteDomain call (accidental, malicious, buggy automation) destroys the domain irreversibly. Production domains require an explicit deletion-protection flag or SCP guard.

**Remediation:** Apply a tag-based SCP that denies DeleteDomain on domains tagged deletion_protection=true. Or use an IAM policy condition denying the action when the tag is set.

---

### CTL.OPENSEARCH.EBS.GP2.IO.HEAVY.001

**OpenSearch Domain Uses gp2 EBS For IO-Heavy Workload**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** capacity
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5; soc2: A1.1;

OpenSearch domain with index-heavy / search- heavy workload uses `gp2` EBS volume type. gp2 IOPS scale with volume size (3 IOPS/GB); IO-heavy workloads exhaust burst credits and fall back to baseline IOPS, causing latency. gp3 (provisioned IOPS independent of size) or io2 (high-perf) are appropriate.

**Remediation:** Migrate to gp3 (matches gp2 cost, independent IOPS). For very heavy: io2. Update via UpdateDomainConfig --ebs-options.

---

### CTL.OPENSEARCH.ENCRYPT.001

**Encryption at Rest Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

OpenSearch domains must have encryption at rest enabled using AWS KMS. Unencrypted data at rest is exposed if the underlying storage is compromised or if snapshots are shared.

**Remediation:** Enable encryption at rest in the domain configuration. Note: encryption at rest can only be enabled at domain creation time for some versions. If needed, create a new domain with encryption enabled and migrate data.

---

### CTL.OPENSEARCH.ENCRYPT.002

**Node-to-Node Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; soc2: CC6.7;

OpenSearch domains must have node-to-node encryption enabled. Without it, data transmitted between nodes within the cluster travels unencrypted, exposing it to interception on the internal network. Node-to-node encryption is a prerequisite for fine-grained access control.

**Remediation:** Enable node-to-node encryption in the domain configuration. This is required for fine-grained access control.

---

### CTL.OPENSEARCH.ENGINE.DRIFT.ENVS.001

**OpenSearch Engine Version Drifts Across Environment Tiers**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32, A.8.8; nist_800_53_r5: CM-3, SI-2; soc2: CC8.1;

OpenSearch domain in production runs an engine version older than the same workload's non- production / staging domain. Operators tested in dev, validated in staging on a newer version, then never upgraded production. Production now lacks fixes that have been rolled out to lower environments.

**Remediation:** Upgrade production to match non-prod. Future: enforce version-pinning across environments via IaC / pipeline policy.

---

### CTL.OPENSEARCH.ENGINE.EOL.001

**OpenSearch Engine Version End-Of-Life**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.8; nist_800_53_r5: SI-2, RA-5; pci_dss_v4.0: 6.2, 6.3; soc2: CC7.1, CC8.1;

OpenSearch domain runs an engine version that is end-of-life (e.g., Elasticsearch 5.x, 6.x, 7.1-7.9). EOL versions receive no security patches; known CVEs remain unfixed. AWS forced-update windows for EOL versions are hard deadlines with limited rollback.

**Remediation:** Plan blue-green migration to current OpenSearch major version. Test on non-prod first; allow weeks for cluster-state migration.

---

### CTL.OPENSEARCH.ENGINE.OUTDATED.001

**OpenSearch Engine Version Behind Latest Patch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.8; nist_800_53_r5: SI-2; pci_dss_v4.0: 6.2; soc2: CC7.1;

OpenSearch domain runs an engine version that is one or more minor / patch releases behind the latest available. Newer versions include security patches, performance fixes, and plugin compatibility updates. Stale engine = accumulated CVE exposure.

**Remediation:** Apply pending service software update via StartServiceSoftwareUpdate. AWS handles rolling restart; cluster remains available.

---

### CTL.OPENSEARCH.ES7.NOT.MIGRATED.001

**OpenSearch Domain Still Running Elasticsearch 7.x Engine**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.8; nist_800_53_r5: SI-2, CM-3; pci_dss_v4.0: 6.2; soc2: CC7.1, CC8.1;

Domain is still running an Elasticsearch 7.x engine and has not migrated to OpenSearch 1.x / 2.x. AWS no longer ships new features for ES 7.x; future security updates may also taper off. Migration to OpenSearch is a one-time activity that requires planning; delay compounds.

**Remediation:** Plan blue-green to OpenSearch 2.x. Test in non-prod; verify plugin / client compatibility; allow weeks for migration.

---

### CTL.OPENSEARCH.FGAC.001

**Fine-Grained Access Control Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch domains must have fine-grained access control (FGAC) enabled. Without FGAC, access is controlled only by resource-based policies which cannot restrict access at the index, document, or field level. FGAC enables role-based access control within the cluster, authentication via IAM or internal users, and audit logging of all access decisions.

**Remediation:** Enable fine-grained access control in the domain security configuration. This requires enabling node-to-node encryption and encryption at rest as prerequisites.

---

### CTL.OPENSEARCH.FGAC.NOUSERS.001

**OpenSearch FGAC Enabled But Internal User Database Empty**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: AC-2, AC-3; pci_dss_v4.0: 8.2.1; soc2: CC6.1, CC6.6;

OpenSearch domain has fine-grained access control enabled but the internal user database is empty (only the default master). FGAC was turned on as a checkbox to satisfy compliance, but no users / role mappings exist to actually use it. Either all access falls back to the master credential (single shared credential) or all data-plane calls fail (silent outage when first FGAC-aware client reaches it).

**Remediation:** Provision per-tenant internal users or map IAM roles to FGAC roles via opensearch-cli / Dashboards Security plugin. Decide whether internal-user DB is the source of truth or whether SAML / Cognito / IAM is.

---

### CTL.OPENSEARCH.HTTPS.001

**HTTPS Must Be Enforced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch domains must enforce HTTPS for all connections. Without HTTPS enforcement, clients can connect over unencrypted HTTP, exposing queries, results, and credentials in transit.

**Remediation:** Enable HTTPS enforcement in the domain endpoint options. Set the TLS security policy to Policy-Min-TLS-1-2-PFS-2023-10 for current best practice.

---

### CTL.OPENSEARCH.IAC.DRIFT.001

**OpenSearch Domain Configuration Modified Outside IaC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CM-8; soc2: CC8.1, CC7.1;

OpenSearch domain's most recent configuration change came from a principal that is not the IaC automation role (Terraform / CloudFormation service role). Direct console / CLI changes bypass IaC review and create state divergence that the next IaC apply will overwrite — or worse, that operators will paper over by hand-modifying the IaC source to match.

**Remediation:** Identify the change via CloudTrail (filter eventName=UpdateDomainConfig). Reproduce in IaC; revert if unauthorized. Add a CloudWatch alarm: UpdateDomainConfig events from non-IaC principals.

---

### CTL.OPENSEARCH.IAM.NOTAGAUTH.001

**OpenSearch IAM Permissions Not Scoped By Resource Tag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.3;

Organization's IAM policies for OpenSearch (`es:*` actions) are not scoped using `aws:ResourceTag/<key>` conditions. Single IAM role grants apply to every OpenSearch domain in the account; per-team / per-env isolation impossible without per-domain policy proliferation. Tag-based access control is the AWS-recommended pattern.

**Remediation:** Add aws:ResourceTag conditions to IAM policies:
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/team": "${aws:PrincipalTag/team}"
    }
  }

---

### CTL.OPENSEARCH.IDLE.001

**OpenSearch Domain Idle With No Searchable-Document Change**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-7, CM-8; soc2: CC8.1;

OpenSearch domain has had no `SearchableDocuments` change for 30+ days and no Reserved Instance commitment justifying the spend. Domain bills full instance + EBS rates for an unused workload. Common cause: workload migrated, decommission was deferred.

**Remediation:** Take final snapshot; document decision; DeleteDomain. Or if retention is deliberate, downsize to smallest viable instance class.

---

### CTL.OPENSEARCH.INCOMPLETE.001

**Complete Data Required for OpenSearch Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

OpenSearch domain safety cannot be proven when access control data is missing from the snapshot. The extractor must populate search_service.access.publicly_accessible to evaluate public exposure controls.

**Remediation:** Re-run the extractor with OpenSearch permissions: es:DescribeDomain, es:DescribeDomainConfig.

---

### CTL.OPENSEARCH.ISM.COLD.UNAVAILABLE.001

**OpenSearch ISM Policy Transitions To Cold With Cold Storage Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.30; nist_800_53_r5: CM-2; soc2: CC8.1;

OpenSearch ISM policy declares a transition to cold storage but the domain has cold storage disabled. Same failure mode as warm-without- ultrawarm; policy steps stuck or fail.

**Remediation:** Enable cold storage tier on domain (engine 1.3+) or revise ISM policy to skip cold transition.

---

### CTL.OPENSEARCH.ISM.MISSING.001

**OpenSearch Time-Series Indices Have No ISM Policy Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-2; iso_27001_2022: A.5.30; nist_800_53_r5: CP-2, CM-2; soc2: CC8.1, A1.1;

OpenSearch domain has time-series indices (logs, metrics, daily / hourly index pattern) with no ISM (Index State Management) policy attached. Indices grow unboundedly; storage fills; flood-stage hits. Even when an ISM policy exists, mismatched `default_state` causes new indices to enter the wrong phase and never transition.

**Remediation:** Create ISM policy with rollover, force_merge, warm/cold transitions, and delete state. Attach to index template so new indices inherit. Verify with _plugins/_ism/policies.

---

### CTL.OPENSEARCH.ISM.NOFAILURE.PATH.001

**OpenSearch ISM Policy Lacks Failure Transition Path**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CM-3, AU-12; soc2: CC8.1, CC7.3;

OpenSearch ISM policy has no `error_notification` or transition handling for `Failed` state. When a step fails (e.g., snapshot to a missing repo, force_merge on a node-pressured cluster), the policy stops mid-flight; indices accumulate in failed state forever, blocking future state transitions on those indices. Common with policies authored by trial and error.

**Remediation:** Add error_notification (SNS / email) or explicit retry/fail transitions. Audit failed-state indices weekly:
  GET _plugins/_ism/explain/* | jq '.[]
    | select(.state.name=="failed")'

---

### CTL.OPENSEARCH.ISM.NOSNAPSHOT.DELETE.001

**OpenSearch ISM Delete State Has No Pre-Delete Snapshot Action**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13; nist_800_53_r5: CP-9; soc2: CC7.4, A1.2;

OpenSearch ISM policy's `delete` state runs without a preceding `snapshot` action, or the snapshot action references a repository different from the compliance-retained one. Once an index reaches delete state, data is irrevocable; recovery is impossible if no snapshot was taken first or if the snapshot went to a short-retention repo.

**Remediation:** Add snapshot action before delete:
  "actions": [
    {"snapshot": {"repository": "<long-ret-repo>",
     "snapshot": "{{ctx.index}}-final"}},
    {"delete": {}}
  ]

---

### CTL.OPENSEARCH.ISM.WARM.UNAVAILABLE.001

**OpenSearch ISM Policy Transitions To Warm With UltraWarm Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.30; nist_800_53_r5: CM-2; soc2: CC8.1;

OpenSearch ISM policy declares a `hot → warm` transition but the domain has UltraWarm storage tier disabled. Policy steps fail silently or block; indices stuck in hot tier past their intended lifecycle. Common after policy was authored on a domain with UltraWarm enabled and copied to one without.

**Remediation:** Either enable UltraWarm on the domain or revise ISM policy to skip warm transition. For cost-sensitive workloads, UltraWarm is the right answer.

---

### CTL.OPENSEARCH.KIBANA.001

**OpenSearch Dashboards Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

OpenSearch Dashboards (Kibana) endpoints must not be publicly accessible without authentication. Dashboards provide a query interface to the entire cluster — a public, unauthenticated dashboard is functionally equivalent to giving attackers a SQL client connected to your database. The Darkbeam breach exposed both the Elasticsearch API and the Kibana dashboard to the public internet.

**Remediation:** Restrict Dashboards access via VPC, Cognito authentication, or SAML federation. Enable fine-grained access control to enforce role-based access within Dashboards.

---

### CTL.OPENSEARCH.LOG.001

**Audit Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; soc2: CC7.1;

OpenSearch domains must have audit logging enabled to track authentication attempts, access decisions, and data operations. Without audit logging, unauthorized access to the cluster cannot be detected or investigated after the fact.

**Remediation:** Enable audit logging in the domain configuration. Configure a CloudWatch log group as the destination. Fine-grained access control must be enabled as a prerequisite for audit logging.

---

### CTL.OPENSEARCH.LOG.CROSSACCT.TRUST.MISSING.001

**OpenSearch Cross-Account Log Delivery Role Lacks Required Trust**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.15; nist_800_53_r5: AU-12; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

OpenSearch domain configured for cross-account log delivery (logs go to a CloudWatch group in a central observability account) — but the delivery role in the destination account does not include the OpenSearch service principal in its trust policy. Logs are generated in the domain's account but cannot be assumed-into the destination account; events drop silently. Common after re-org / account splits where the central account got the role created without trust for the new domain accounts.

**Remediation:** Update the delivery role's trust policy in the destination account to include es. amazonaws.com plus the source account ID:
  "Principal": {"Service": "es.amazonaws.com"},
  "Condition": {
    "StringEquals": {"aws:SourceAccount": "111122223333"}
  }

---

### CTL.OPENSEARCH.LOG.RETENTION.BEFORE.EXPORT.001

**OpenSearch Log Group Retention Expires Before Scheduled S3 Export**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

OpenSearch domain log group has retention shorter than the cadence of its scheduled S3 export job. Events age out of the CloudWatch group before the export task copies them to S3 long-term storage. The export job picks up only the retained events, leaving a gap between the export window and what was actually generated. Common pattern: 7-day retention with weekly export job that runs every Monday — events from Tuesday-Sunday survive but the prior week's Monday events are gone.

**Remediation:** Increase log group retention to >= (export cadence + buffer). 7-day retention with daily export is fine; 7-day with weekly export needs at minimum 14-day retention. Or switch to streaming export (Kinesis Firehose) instead of batch.

---

### CTL.OPENSEARCH.MAINTENANCE.WINDOW.UNSET.001

**OpenSearch Domain Maintenance Window Not Set Or In Business Hours**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-3, MA-2; soc2: CC8.1, A1.2;

OpenSearch domain has no auto-tune / software- update maintenance window configured, or the configured window falls in business hours. Without a deliberate window, AWS picks a default that may overlap peak traffic; updates cause user-visible degradation. Operators rely on "we'll see when it happens" — guaranteed surprise.

**Remediation:** Configure off-peak maintenance window via UpdateDomainConfig --auto-tune-options desired-state ENABLED + maintenance-schedule in low-traffic hours (per your timezone).

---

### CTL.OPENSEARCH.MASTER.COUNT.NONQUORUM.001

**OpenSearch Master Node Count Does Not Form Quorum**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5, CP-7; soc2: A1.1, A1.2;

OpenSearch domain with dedicated masters has master count of 1 or 2. Master count of 1 is a single point of failure; count of 2 cannot form quorum after losing 1 (split-brain risk). Production-tier domains require 3 masters minimum to tolerate single-node failure with quorum.

**Remediation:** Update master count to 3 via UpdateDomainConfig --cluster-config dedicated-master-count=3. Confirms quorum after single-node loss.

---

### CTL.OPENSEARCH.MASTER.NODEDICATED.001

**OpenSearch Production Domain Has No Dedicated Master Nodes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5; soc2: A1.1, A1.2;

OpenSearch production-tier domain has no dedicated master nodes. Without dedicated masters, cluster-state operations (shard reallocation, mapping update, ISM transitions) contend with user query load on the same nodes. Heavy workload episodes drag the master process and can cause split-brain or stalled state propagation.

**Remediation:** Configure 3 dedicated masters (m6g.large or larger depending on cluster size). Update via UpdateDomainConfig --cluster-config dedicated-master-enabled.

---

### CTL.OPENSEARCH.MASTER.PASSWORD.AGE.001

**OpenSearch Master User Password Older Than 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.6, 8.3.9; soc2: CC6.1, CC6.6;

OpenSearch FGAC password-based master user credential has not been rotated in over 90 days. Long-lived shared credentials accumulate exposure risk: leak surface (logs, vault history, operator memory), revocation blast radius (rotation breaks every consuming service), and audit-trail opacity (multiple callers sharing one credential). Even when password auth is unavoidable, rotation cadence bounds the leakage window.

**Remediation:** Rotate via UpdateDomainConfig --advanced- security-options master-user-password. Coordinate with consuming services to update their stored credential. Long-term: migrate to IAM-role-based master.

---

### CTL.OPENSEARCH.MASTER.PASSWORD.AUTH.001

**OpenSearch Master User Authenticates Via Password Not IAM Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, IA-5; pci_dss_v4.0: 8.2.1, 8.3.1; soc2: CC6.1, CC6.6;

OpenSearch FGAC master user is provisioned with a password (internal user database) instead of mapping to an IAM role. Password-based master auth means: the credential lives somewhere (Secrets Manager, vault, or worse), can be exfiltrated, and cannot be rotated automatically alongside the calling service's identity. IAM role mapping ties the master to AWS principal identity — rotated automatically, audited via CloudTrail, no shared secret.

**Remediation:** Update the FGAC master configuration to reference an IAM role ARN as the master. Decommission the password-based master once the role-based master is verified working. Document the break-glass account separately.

---

### CTL.OPENSEARCH.MASTER.SAME.INSTANCE.001

**OpenSearch Master And Data Nodes On Same Instance Type**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5; soc2: A1.1, A1.2;

OpenSearch domain has dedicated masters but uses the same instance type / class for both master and data nodes. The two roles have different resource profiles: masters need memory and quick failover, data nodes need IO and bulk memory. Co-typing them either oversizes masters (cost) or undersizes data (perf).

**Remediation:** Pick master instance type appropriate to shard count (m6g.large baseline), separately from data instance type (r6g.* / i3.* for IO-heavy). Document the sizing decisions.

---

### CTL.OPENSEARCH.MASTER.UNDERSIZED.001

**OpenSearch Master Instance Type Undersized For Cluster Shard Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5; soc2: A1.1;

OpenSearch dedicated master instance type is too small for the cluster's shard count. Master memory grows with shards (rough rule: ~10 MB heap per shard); a small master with 10K+ shards spends most of its time in GC. Symptoms: cluster-state delays, ISM transitions slow, mapping updates stall.

**Remediation:** Compute master heap need based on shard count; right-size to next instance class (m6g.large → m6g.xlarge → m6g.2xlarge). Reduce shard count if possible (force_merge, rollover policy).

---

### CTL.OPENSEARCH.ML.UNSAFE.001

**OpenSearch ML Commons Plugin Auth Or Versioning Unsafe**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.5, A.8.32; nist_800_53_r5: AC-3, CM-3; soc2: CC6.1, CC8.1;

OpenSearch ML Commons plugin enabled with no authentication on `_predict` endpoint, or ML model deployed without version pinning. Anonymous prediction calls = abuse / cost amplification. Unpinned models = silent rollovers that change downstream behavior without notice.

**Remediation:** Restrict _predict to authenticated callers via FGAC role mapping. Pin model versions in production deployments; promote new versions through staged rollout.

---

### CTL.OPENSEARCH.NOREPLICAS.001

**OpenSearch Production Indices Have Zero Replicas**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.14; nist_800_53_r5: CP-9, SC-5; soc2: A1.1, A1.2;

OpenSearch production domain has indices with `number_of_replicas: 0` (no replicas). Single-replica defaults exist for a reason: primary shard loss without replicas means data unavailability. With multi-AZ topology but zero replicas, AZ failure still loses shards.

**Remediation:** Set index template default number_of_replicas to 1 minimum (2 for high-availability tier). Apply via:
  PUT /_template/<name> {"settings": {
    "number_of_replicas": 1 }}

---

### CTL.OPENSEARCH.NOTAGS.001

**OpenSearch Domain Missing Cost-Allocation Or Compliance Tags**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.5.30; nist_800_53_r5: CM-8, PM-3; soc2: CC8.1;

OpenSearch domain has no `cost-center`, `team`, `owner`, or `data-classification` tag. Cost allocation can't roll up by team / project; compliance scoping (HIPAA / PCI / SOC2 / GDPR) requires manual lookup for each domain. Org-standard tag set is the foundation of governance reporting.

**Remediation:** Apply tags: cost-center, team, owner, data-classification, compliance-scope, environment. Activate AWS Cost Allocation Tags via Billing Console.

---

### CTL.OPENSEARCH.NOTIFY.HTTP.001

**OpenSearch Notification Plugin Webhook Over HTTP Or Async-Search Unbounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-8; iso_27001_2022: A.8.24; nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

OpenSearch notification plugin webhook configured over plain HTTP (cleartext alert bodies) or Async-Search results retained indefinitely (storage growth + privacy). Webhook bodies often contain alert content including sensitive data; HTTP makes it visible to network observers.

**Remediation:** Reconfigure webhooks to HTTPS endpoints. Set async_search.maximum_response_size and TTL via cluster settings.

---

### CTL.OPENSEARCH.NOTIFY.SUBSCRIBER.001

**OpenSearch Alarms Route To Topic With No Human Subscriber**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, IR-6; soc2: CC7.2, A1.1;

OpenSearch domain CloudWatch alarms route to an SNS topic / EventBridge rule that has no active subscriber (or only subscribers that are themselves dormant). Alarms fire and drain into the void; on-call learns of cluster issues via downstream complaints. Common cause: subscriber email account deactivated when team member left.

**Remediation:** Audit SNS subscriptions on every alarm- routed topic. Confirm each email / Slack / PagerDuty endpoint reaches a person. Quarterly review.

---

### CTL.OPENSEARCH.OPERATOR.ESSTAR.PERMANENT.001

**OpenSearch Operator Break-Glass Role With es:* Permanently Active**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-2, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.3;

Organization has a break-glass IAM role with `es:*` permissions that is permanently assumable rather than gated behind a just-in-time elevation flow. Permanent break-glass = always-on cluster-admin capability for any caller in the trust policy. Compromise of any of those callers yields domain admin without further escalation.

**Remediation:** Move break-glass behind JIT elevation (AWS IAM Identity Center / Permission Sets with approval workflow). Track elevation events in audit log.

---

### CTL.OPENSEARCH.ORPHAN.001

**OpenSearch-Tagged Resources Orphaned After Domain Deletion**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-8; soc2: CC8.1;

AWS account has resources tagged for an OpenSearch domain that no longer exists: orphan snapshot S3 bucket, VPC endpoint, CloudWatch Log group. Each accrues cost forever. The orphan KMS key (if any) is separately tracked by KMS lifecycle.

**Remediation:** Inventory orphan resources via tag query `kubernetes.io/cluster/...` equivalent for OS: `aws:opensearch:domain-name` matching deleted domain. Snapshot then delete.

---

### CTL.OPENSEARCH.OSIS.BUFFER.UNSAFE.001

**OpenSearch Ingestion Pipeline Lacks Persistent Buffer Or DLQ**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.13, A.8.16; nist_800_53_r5: AU-12, CP-9; soc2: CC7.2, A1.2;

OpenSearch Ingestion pipeline has persistent buffer disabled (data loss on restart) or Dead-Letter Queue disabled (poison-pill data silently dropped). Either makes the pipeline silently lossy under non-happy-path conditions; ingest counts diverge from upstream produce counts without alarm.

**Remediation:** Enable both via UpdatePipeline --buffer-options EnablePersistentBuffer=true and configure DLQ S3 bucket. Set up alarm on DLQ object count.

---

### CTL.OPENSEARCH.OSIS.NOVPC.001

**OpenSearch Ingestion Pipeline Has No VPC Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7, SC-8; pci_dss_v4.0: 1.3.1, 4.2.1; soc2: CC6.1, CC6.7;

OpenSearch Ingestion (OSIS) pipeline has no VPC config; ingest data path traverses the public network. Source and sink both visible to AWS-side observability, but the bytes themselves transit a path operators don't control.

**Remediation:** Re-create pipeline with vpc_options pointing at private subnets and a security group that scopes ingress.

---

### CTL.OPENSEARCH.OSIS.SECRETS.PLAIN.001

**OpenSearch Ingestion Pipeline Stores Secrets In Plaintext Config**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-28; pci_dss_v4.0: 8.3.2; soc2: CC6.1;

OpenSearch Ingestion pipeline configuration contains plaintext credentials (API keys, database passwords, third-party tokens) rather than referencing AWS Secrets Manager. The pipeline definition is auditable / readable by anyone with osis:GetPipeline; secrets exfiltrate via inventory query.

**Remediation:** Move secrets to Secrets Manager; reference via ${aws_secrets:<secret-name>} in pipeline config. Rotate any secrets that were historically stored in plaintext.

---

### CTL.OPENSEARCH.OSIS.SOURCE.UNSAFE.001

**OpenSearch Ingestion Pipeline Source Configuration Unsafe**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-7, SC-8, AC-3; pci_dss_v4.0: 1.3.4, 4.2.1; soc2: CC6.1, A1.1;

OpenSearch Ingestion pipeline has unsafe source config: auto-scaling min == max (no headroom), cross-account source without trust validation, or Kafka source without TLS. Each variant produces a brittle / unauthenticated / cleartext ingest path.

**Remediation:** Auto-scale: set max > min for headroom. Cross-account: add explicit trust validation. Kafka: enable TLS via bootstrap_servers with security_protocol.

---

### CTL.OPENSEARCH.OVERPROVISIONED.001

**OpenSearch Domain Sustained CPU Below Right-Sizing Threshold**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7, SC-5; soc2: CC8.1;

OpenSearch domain has sustained CPU < 5% averaged across data nodes over the last 30 days; clearly over-provisioned. Right- sizing recommendations from Trusted Advisor / Compute Optimizer go unread; the organization pays for headroom that has never been used.

**Remediation:** Right-size to next smaller instance class via blue-green. Verify capacity headroom on new sizing before next traffic peak.

---

### CTL.OPENSEARCH.PAINLESS.INLINE.001

**OpenSearch Inline Painless Scripts Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.8; nist_800_53_r5: SI-2, AC-3; pci_dss_v4.0: 6.2; soc2: CC6.1, CC7.1;

OpenSearch domain has inline Painless script execution enabled. Painless is sandboxed but the sandbox has had documented escape primitives in past CVEs; allowing untrusted callers to submit inline scripts is an accepted attack surface. Production-tier domains should restrict to stored, signed scripts.

**Remediation:** Set script.allowed_types: "stored" via cluster settings. Migrate any inline- script callers to stored scripts.

---

### CTL.OPENSEARCH.PLUGIN.UNSUPPORTED.001

**OpenSearch Plugins Or Custom Packages Not Compatible With Engine**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1;

OpenSearch domain has plugins / custom packages pinned to engine version that no longer matches the cluster's actual engine, or has custom packages out of sync with engine. Plugin loaders fall back to compat mode (slow, fewer features) or fail to load entirely. Symptoms: custom analyzers fail, ML Commons predictions return errors, async-search timeout.

**Remediation:** Update plugin pins to match engine version. Re-deploy custom packages built for the current engine. Verify with GET _cat/plugins.

---

### CTL.OPENSEARCH.PLUGIN.UNTRUSTED.001

**OpenSearch Custom Plugin From Untrusted Source Or Signature Verification Off**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; iso_27001_2022: A.8.8, A.8.34; nist_800_53_r5: SI-7, SI-2; pci_dss_v4.0: 6.4; soc2: CC6.1, CC7.1;

OpenSearch domain runs a custom plugin from an unverified source, or has plugin signature verification disabled. Plugins execute with full cluster privileges; supply-chain attack on a plugin compromises the entire domain.

**Remediation:** Vet plugin source / build pipeline; enable signature verification. Pin plugin version to a known-good build. Audit plugin list against an organizational allowlist.

---

### CTL.OPENSEARCH.POLICY.ACTION.WILDCARD.001

**OpenSearch Access Policy Grants Action Wildcard To Non-Admin Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, AC-3; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

OpenSearch domain access policy grants `es:*` on `Resource: "*"` (or domain ARN with `/*`) to a principal that is not the admin / break-glass role. The wildcard includes data-plane reads, writes, deletes, and management API calls (UpdateDomainConfig, DeleteDomain). Non-admin roles getting `es:*` is the most common privilege-escalation gap on managed domains.

**Remediation:** Replace es:* with the minimum action set the role actually needs (e.g., es:ESHttpGet, es:ESHttpPost on /_search). Reserve es:* for a documented break-glass role with separate sign-off requirements.

---

### CTL.OPENSEARCH.POLICY.CROSSACCOUNT.NOEXTERNAL.001

**OpenSearch Cross-Account Principal Without ExternalId Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.6;

OpenSearch domain access policy permits a principal in another AWS account without an `sts:ExternalId` condition or equivalent confused-deputy guard. The classic confused-deputy attack: a third party with any role in the foreign account can assume that role and reach the domain. ExternalId binds the trust to a specific tenant/integration.

**Remediation:** Add an sts:ExternalId condition matching the integration's known external ID:
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "tenant-abc-9f2c"
    }
  }
Distribute the ExternalId out-of-band to the integrating party.

---

### CTL.OPENSEARCH.POLICY.CROSSACCOUNT.WILDCARD.001

**OpenSearch Cross-Account Principal Granted Action Wildcard**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1, 7.2.4; soc2: CC6.1, CC6.3;

OpenSearch domain access policy grants `es:*` (or any other action wildcard) to a principal in another AWS account. Cross-account + action wildcard combines the worst of both: an attacker who gets any role in the foreign account assumes it and inherits full domain control. Most cross-account integrations need a narrow set of actions (commonly `es:ESHttpGet`, sometimes `es:ESHttpPost`); operators paste `es:*` for expediency during integration setup and never narrow it.

**Remediation:** Narrow the cross-account grant to the specific actions needed by the integration. Combine with sts:ExternalId condition for confused-deputy protection.

---

### CTL.OPENSEARCH.POLICY.DELETE.READONLY.001

**OpenSearch Access Policy Permits Delete Action To Read-Only Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, AC-3; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

OpenSearch domain access policy permits `es:ESHttpDelete` to a role labeled or scoped as read-only. ESHttpDelete maps to HTTP DELETE on the REST API: deleting indices, documents, templates, ISM policies, snapshots. A read-only role with delete is no longer read-only; the label drift is invisible to the IAM-policy-only reviewer who never opens the domain access policy.

**Remediation:** Remove ESHttpDelete from the read-only role's granted actions. Move delete capability to a separate write role with auditable change process.

---

### CTL.OPENSEARCH.POLICY.ESHTTP.WILDCARD.001

**OpenSearch Access Policy Grants es:ESHttp* To Read-Only Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

OpenSearch domain access policy grants `es:ESHttp*` (all HTTP verbs) to a role labeled read-only. The wildcard includes ESHttpPost, ESHttpPut, and ESHttpDelete — write and delete surface — even though the role's name suggests reads only. ESHttp* is a common shortcut that hides the actual capability under a wildcard that reviewers gloss over.

**Remediation:** Replace the wildcard with explicit verbs:
  es:ESHttpGet, es:ESHttpHead
Reserve write/delete verbs for separate write-tier roles. AWS IAM Access Analyzer flags this pattern as least-privilege violation.

---

### CTL.OPENSEARCH.POLICY.IP.DYNAMIC.001

**OpenSearch Access Policy IP Allowlist Permits Dynamic ISP Range**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.6;

OpenSearch domain access policy `aws:SourceIp` allowlist includes a CIDR range that belongs to a consumer / dynamic-ISP / cloud-provider netblock rather than a static corporate egress. Examples: `Comcast` residential ranges, AWS public IPs in bulk, Cloudflare proxy ranges, large /8 blocks. These ranges rotate, are shared across millions of hosts, and are commonly used by attackers. The allowlist appears restrictive at policy review but effectively permits any client behind the listed ISP.

**Remediation:** Replace dynamic ranges with the static corporate NAT egress / VPN gateway addresses. For VPC domains, use aws:SourceVpce instead of aws:SourceIp. Inventory all CIDRs in the policy against an IP-intelligence source (MaxMind, Spamhaus DROP, AWS IP ranges JSON) and remove any range marked as ISP / cloud / proxy.

---

### CTL.OPENSEARCH.POLICY.RI.RECON.001

**OpenSearch Describe Permissions Over-Shared To Read-Only Roles**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, AC-22; soc2: CC6.1, CC7.2;

IAM permissions on the domain include `es:DescribeReservedElasticsearchInstances`, `es:ListDomainNames`, and `es:DescribeElasticsearchDomain*` granted broadly (e.g., to all read roles or all authenticated users). Describe APIs reveal topology — instance types, counts, RI commitments, account inventory — that an attacker uses for cost reconnaissance, privilege-escalation target selection, and detection-evasion planning.

**Remediation:** Restrict es:Describe* and es:List* to roles that have an operational need (cost dashboards, inventory tooling). Block from generic read roles. Audit via:
  aws iam simulate-principal-policy
    --policy-source-arn <role>
    --action-names es:DescribeElasticsearchDomain

---

### CTL.OPENSEARCH.POLICY.SOURCEIP.STRINGEQUALS.001

**OpenSearch Access Policy Uses StringEquals On aws:SourceIp**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.6;

OpenSearch domain access policy condition uses `StringEquals` (or `StringLike`) operator on `aws:SourceIp`. AWS evaluates `aws:SourceIp` as an IP-address value, requiring `IpAddress` / `NotIpAddress` operators; a `StringEquals` compare on the same key compares the request's IP string to the literal CIDR string. The condition almost never matches (request IP is `203.0.113.7`, CIDR is `203.0.113.0/24`) so the deny / allow effect silently inverts. Common copy-paste error from IAM policy examples that use StringEquals on other condition keys.

**Remediation:** Replace StringEquals/StringLike with IpAddress / NotIpAddress:
  "Condition": {
    "IpAddress": { "aws:SourceIp": "203.0.113.0/24" }
  }
Lint policies before applying. AWS IAM Access Analyzer flags this as a finding (PolicyValidation USE_IP_CONDITION).

---

### CTL.OPENSEARCH.POLICY.STALE.RULE.001

**OpenSearch Access Policy Has Stale Temporary Allow Rule**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.27; nist_800_53_r5: AC-6, CA-7; soc2: CC6.1, CC8.1;

OpenSearch domain access policy contains a statement marked or commented as temporary (operator's home IP, contractor's office, vendor CIDR, debugging exception) that has been in place for more than 90 days. Temporary rules accumulate over years; nobody owns removing them. Each stale rule is an unreviewed allow path.

**Remediation:** Quarterly access-policy review: identify each statement marked temporary; either promote to a permanent rule (with documented owner) or remove. Encode expiry dates in policy statement Sids ("temp-2025Q1-corp-ip") so review is mechanical.

---

### CTL.OPENSEARCH.POLICY.UNVERSIONED.001

**OpenSearch Access Policy Not Version-Pinned In IaC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CM-8; soc2: CC8.1, CC7.1;

OpenSearch domain access policy is managed out-of-band — applied via console or ad-hoc CLI without an IaC source of truth (Terraform / CloudFormation / CDK). History of policy changes is unreviewable; rollback to a known-good state requires reconstructing the policy from CloudTrail. Access-policy drift is the most common path to silent permission expansion.

**Remediation:** Move the policy under Terraform / CDK / CloudFormation. Use a `policy_version` tag or a Sid suffix to track the deployed version. Configure CI/CD to detect drift via `terraform plan` and alert on diff.

---

### CTL.OPENSEARCH.POLICY.UPDATECONFIG.NONADMIN.001

**OpenSearch UpdateDomainConfig Permission Granted To Non-Admin**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, CM-3; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3, CC8.1;

OpenSearch domain policy or attached IAM policy grants `es:UpdateElasticsearchDomainConfig` (or `es:UpdateDomainConfig`) to a role that is not the admin / break-glass role. UpdateDomainConfig modifies access policies, encryption settings, network config, log delivery, and cluster topology. Compromise of any role with this action ≈ control-plane takeover of the domain.

**Remediation:** Restrict UpdateDomainConfig to a documented admin role with break-glass review. Prefer IaC-driven config changes; revoke direct UpdateDomainConfig from automation roles.

---

### CTL.OPENSEARCH.POLICY.WILDCARD.OPEN.IP.001

**OpenSearch Access Policy Wildcard Principal With Open IP Condition**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 1.3.1, 1.3.2; soc2: CC6.1;

OpenSearch domain access policy uses `Principal: "*"` with an `aws:SourceIp` condition that resolves to `0.0.0.0/0` (or includes a `/0` CIDR among allowed ranges). The condition is intended to lock the policy down to a known IP set, but the actual CIDR is open or includes an open catch-all. This is functionally identical to a wildcard principal with no condition. Often the result of operator copy-paste from public examples or a default `0.0.0.0/0` left from initial setup.

**Remediation:** Replace 0.0.0.0/0 with the actual trusted CIDR list (corporate gateway, NAT, VPN). For VPC domains, use aws:SourceVpc or aws:SourceVpce instead of IP-based conditions. Audit access policies during quarterly review:
  aws es describe-domain-config --domain-name <name>
    --query 'DomainConfig.AccessPolicies'

---

### CTL.OPENSEARCH.PRIVATELINK.PRINCIPAL.WILDCARD.001

**OpenSearch PrivateLink Endpoint Policy Permits Any Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7, AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.1, CC6.6;

OpenSearch domain accessed via AWS PrivateLink / Interface VPC Endpoint has an endpoint policy with `Principal: "*"` and no scoping conditions. The endpoint policy is the only network-layer filter on what callers reach the domain through the VPC endpoint; with a wildcard principal, any IAM identity in the consumer VPC's account can invoke the domain via the PrivateLink path. Often default state — the endpoint policy is auto-created open and never tightened.

**Remediation:** Replace Principal: "*" with the specific IAM role / user ARNs that need PrivateLink access. Add aws:SourceVpc / aws:SourceVpce conditions to scope to the intended consumer VPCs:
  "Condition": {
    "StringEquals": {
      "aws:SourceVpce": "vpce-0123456789abcdef0"
    }
  }

---

### CTL.OPENSEARCH.PUBLIC.001

**OpenSearch Domain Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch domains must not have public endpoints accessible from the internet. A publicly accessible domain allows anyone to query, index, or enumerate data without network-level restrictions. The Darkbeam breach (2023) exposed 3.8 billion records from an Elasticsearch instance left unprotected on the public internet. Domains must be deployed within a VPC.

**Remediation:** Migrate the domain to a VPC. Create a new domain with VPC configuration specifying private subnets and security groups. Use VPN, bastion, or AWS PrivateLink for authorized access.

---

### CTL.OPENSEARCH.PUBLIC.AFTER.VPC.001

**OpenSearch Public Endpoint Left Enabled After VPC Migration**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.1;

OpenSearch domain has both a VPC endpoint and a public endpoint enabled simultaneously, with VPC configuration indicating the domain was migrated to VPC. After VPC migration, the public endpoint is supposed to be disabled; leaving it enabled defeats the purpose of the migration. Common pattern: operator runs UpdateDomainConfig to add VPC config, but the original public endpoint is not auto-disabled and operator never returns to remove it.

**Remediation:** Disable the public endpoint via UpdateDomainConfig. Cannot be done in-place if existing clients still hit the public endpoint; coordinate the cutover via DNS / custom endpoint repointing. Confirm with DescribeDomainConfig that endpoint_options no longer includes a public endpoint.

---

### CTL.OPENSEARCH.REGION.UNAUTHORIZED.001

**OpenSearch Domain Deployed In Unauthorized Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.310(d); iso_27001_2022: A.5.10, A.5.34; nist_800_53_r5: AC-3, CA-7; pci_dss_v4.0: 12.10.1; soc2: CC1.5, CC6.1;

OpenSearch domain deployed in an AWS region not on the org's authorized list. Data residency requirements (GDPR EU-only, Schrems II, country-specific data laws) and internal policy (production data only in eu-west-1 / us-east-1) violated. Common cause: dev experiment promoted to production without region review.

**Remediation:** Snapshot in current region, restore in an authorized region, then DeleteDomain in unauthorized region. Cross-region restore requires multi-region KMS key handling.

---

### CTL.OPENSEARCH.ROLE.ALLACCESS.BROAD.001

**OpenSearch all_access Role Mapped To Broad Backend Identity**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, AC-3; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

OpenSearch FGAC built-in `all_access` role is mapped to a broad backend identity — an IAM role shared across many services, an entire SAML group, or `*`. The all_access role is the cluster-admin equivalent on the data plane; broad mapping means any caller with that backend role inherits cluster admin.

**Remediation:** Restrict all_access mapping to a specific documented break-glass IAM role with separate sign-off. Map operational roles to the minimum FGAC role they actually need.

---

### CTL.OPENSEARCH.ROLE.KIBANA.WILDCARD.001

**OpenSearch kibana_user Role Mapped To Wildcard Backend**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.3;

OpenSearch FGAC `kibana_user` role mapped to `*` or to "all authenticated users." Anyone who authenticates to the cluster gets Dashboards access. Combined with FGAC's default tenant configuration, this exposes search / dashboards across all tenants to any auth'd caller.

**Remediation:** Restrict kibana_user to specific IAM roles or SAML groups that need Dashboards access. Multi-tenant clusters: scope per-tenant Dashboards roles separately.

---

### CTL.OPENSEARCH.ROLE.MAPPING.DANGLING.001

**OpenSearch FGAC Role Mapping References Deleted IAM Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-2, AC-6; soc2: CC6.1, CC8.1;

OpenSearch FGAC role mapping references an IAM role / SAML group / Cognito group that no longer exists in the source identity provider. The mapping is dead — no caller assumes the identity. Worse, if the IAM role ARN gets recreated by a different team for a different purpose, the FGAC mapping silently grants the new role's callers whatever the dangling mapping had.

**Remediation:** Quarterly: cross-reference FGAC role mappings against IAM role list. Remove dead mappings. Use IAM Access Analyzer's unused- access findings to drive cleanup cadence.

---

### CTL.OPENSEARCH.ROLLOVER.MISSING.001

**OpenSearch Time-Series Pattern Lacks Rollover Policy Or Index Template**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.30; nist_800_53_r5: CM-2, CP-2; soc2: CC8.1;

OpenSearch domain has time-series index pattern (e.g., `logs-2026.01.01`, `metrics-*`) without a rollover policy, or rollover policy with size-only condition (no max-doc-count fallback), or index template missing. New indices grow past recommended shard size (50 GB), or never rollover when expected, or arrive without expected mappings.

**Remediation:** Create index template with mapping, settings, and ILM/ISM rollover alias. Configure rollover with both size (50gb) AND max_docs (200M) conditions for safety.

---

### CTL.OPENSEARCH.SAML.METADATA.EXPIRED.001

**OpenSearch SAML IdP Metadata Expired Or Near Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-17; soc2: CC7.4, A1.2;

OpenSearch domain SAML configuration's IdP metadata signing certificate is expired or expires within 30 days. SAML responses signed by the IdP fail validation; users cannot log in. SAML metadata must be re-imported when the IdP rotates its signing cert. Operators rarely automate this; when the cert expires, it's a hard outage with login failures across the org.

**Remediation:** Re-import the IdP's current SAML metadata XML via UpdateDomainConfig --advanced-security- options. Set up an EventBridge / EWS reminder 30 days before each expiry; some IdPs (Okta, Azure AD) offer auto-rotation feeds the domain can subscribe to.

---

### CTL.OPENSEARCH.SAML.NOMAPPING.001

**OpenSearch SAML Configured But No Role Mappings**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-2; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, AC-3; pci_dss_v4.0: 8.2.1; soc2: CC6.1, CC6.6;

OpenSearch domain has SAML authentication configured (IdP metadata loaded) but no FGAC role mappings reference SAML group / role attributes. Every SAML-authenticated caller falls to the default FGAC role (commonly `kibana_user` only, sometimes nothing). Either the SAML integration was set up half-finished (operator forgot to map groups) or the organization changed its IdP group structure and the mappings rotted.

**Remediation:** Map FGAC roles to SAML group attributes:
  backend_roles: ["okta-engineers"]
or explicit user attributes. Decide whether to bind by group, role attribute, or role-attribute-list claim.

---

### CTL.OPENSEARCH.SHARD.COUNT.HIGH.001

**OpenSearch Shard Count Per Node Exceeds 1000**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** capacity
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.14; nist_800_53_r5: SC-5; soc2: A1.1;

OpenSearch domain has more than 1000 shards per data node (commonly recommended ceiling). High shard counts inflate cluster-state size, slow shard reallocation, and increase master memory pressure. Common cause: time-series workload with daily indices and many indices, no rollover policy.

**Remediation:** Apply ISM rollover policy + force_merge to reduce shard count. Consolidate small indices via reindex. Aim for fewer, larger shards.

---

### CTL.OPENSEARCH.SLOWLOG.INDEX.OFF.001

**OpenSearch Index Slow Log Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.16; nist_800_53_r5: AU-2, AU-12; soc2: CC7.2, A1.1;

OpenSearch domain has index slow-log delivery to CloudWatch disabled. Index slow-log is the primary signal for ingest regressions (write saturation, mapping explosion, expensive bulk operations). Without it, ingest slowdowns become visible only through ThreadpoolWriteRejected metrics or downstream pipeline backups.

**Remediation:** Enable via UpdateDomainConfig --log-publishing- options INDEX_SLOW_LOGS. Set thresholds appropriate to the bulk size (e.g., 5s warn, 15s info).

---

### CTL.OPENSEARCH.SLOWLOG.SEARCH.OFF.001

**OpenSearch Search Slow Log Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.16; nist_800_53_r5: AU-2, AU-12; soc2: CC7.2, A1.1;

OpenSearch domain has search slow-log delivery to CloudWatch disabled. Slow-log is the primary signal for query-shape regressions (mapping bloat, missing index, expensive aggregations, cross-cluster search latency). Without it, search performance issues become visible only via the customer-side complaint chain.

**Remediation:** Enable via UpdateDomainConfig --log-publishing- options SEARCH_SLOW_LOGS. Set thresholds appropriate to the workload (e.g., 10s warn, 30s info).

---

### CTL.OPENSEARCH.SLOWLOG.THRESHOLD.HIGH.001

**OpenSearch Slow Log Threshold Set Above Practical Trigger**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12; soc2: CC7.2;

OpenSearch domain slow-log threshold (per-tier warn / info / debug / trace) is set high enough that no operational query crosses it. Effectively off, but config inventory and compliance reports show slow-log enabled. Common pattern: operator copy-pasted thresholds from cluster docs (5 minutes default warn) without tuning to actual query SLA.

**Remediation:** Tune thresholds to workload SLA; one common starting point: warn 10s, info 5s, debug 2s, trace 1s for search; halve for index. Review after every major workload change.

---

### CTL.OPENSEARCH.SNAPSHOT.001

**Snapshots Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

OpenSearch domain snapshots must be stored in encrypted repositories. Unencrypted snapshots expose the same data as the live cluster but are often stored with weaker access controls. Snapshot repositories in S3 must use server-side encryption.

**Remediation:** Configure the snapshot repository S3 bucket with default encryption (SSE-S3 or SSE-KMS). Verify the IAM role used for snapshots has minimum required permissions.

---

### CTL.OPENSEARCH.SNAPSHOT.ISM.UNALIGNED.001

**OpenSearch Snapshot Retention Not Aligned With ISM Index Lifecycle**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13; nist_800_53_r5: CP-9; soc2: CC7.4, A1.2;

OpenSearch snapshot retention policy and ISM (Index State Management) index-deletion policy produce inconsistent recovery boundaries: ISM deletes indices at, e.g., 30 days, but snapshots only retain 14 days — recovery for any index 15-30 days old is impossible. Conversely if ISM deletes at 7 days but snapshots retain 365, snapshots accumulate garbage. Retention horizons should align with the longest legitimate recovery scenario.

**Remediation:** Set snapshot retention >= ISM index lifetime + buffer for restore window. Document the chosen recovery horizon in runbook.

---

### CTL.OPENSEARCH.SNAPSHOT.KEY.DRIFT.001

**OpenSearch Snapshot S3 Encryption Key Differs From Domain Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13; soc2: CC6.7;

OpenSearch domain's manual snapshot S3 bucket uses a KMS key different from the domain's at-rest encryption key. During restore, the destination domain (which expects to decrypt with its at-rest key) cannot read snapshots encrypted with a separate key — restore fails unless the target domain is granted access to both keys, or unless the snapshot bucket re-encrypts on the fly. Common cause: bucket was created with default account key and domain was later assigned a tenant-specific key.

**Remediation:** Either update bucket default encryption to match domain key or grant the target domain's role kms:Decrypt on both keys. Document the key custody decision.

---

### CTL.OPENSEARCH.SNAPSHOT.NOCROSSREGION.001

**OpenSearch Manual Snapshot Bucket Has No Cross-Region Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13, A.8.14; nist_800_53_r5: CP-9, CP-7; soc2: CC7.4, A1.2;

OpenSearch domain manual snapshot S3 bucket has no cross-region replication configured. Region-wide AWS event (rare but documented) takes the snapshot bucket offline along with the domain; recovery requires snapshots in a different region. CRR adds cost but the alternative is no DR position for region-wide events.

**Remediation:** Enable S3 CRR to a bucket in another region using a multi-region KMS key. Cost trade-off: storage 2x; alternative: scheduled snapshot copy to second-region bucket via Lambda.

---

### CTL.OPENSEARCH.SNAPSHOT.NOMANUAL.REPO.001

**OpenSearch Domain Has No Manual Snapshot Repository Registered**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13; nist_800_53_r5: CP-9; soc2: CC7.4, A1.2;

OpenSearch domain has only the automated- snapshot repository (cs-automated*) and no manually registered S3 snapshot repository. Automated snapshots cap at 14-day retention and live in AWS-controlled storage; manual repository in S3 is required for any recovery scenario beyond 14 days, cross- region restore, or air-gapped backup.

**Remediation:** Create S3 bucket with KMS encryption + object lock. Register as snapshot repository via _snapshot/<repo>. Schedule daily / weekly snapshot creation via Curator or ISM "snapshot" action.

---

### CTL.OPENSEARCH.SNAPSHOT.REPO.PATH.COLLISION.001

**OpenSearch Has Multiple Snapshot Repositories Pointing To Same S3 Path**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13; nist_800_53_r5: CP-9, CM-2; soc2: CC8.1;

OpenSearch domain has more than one registered snapshot repository pointing to the same S3 bucket / base path. Snapshot writes from each repo race to overwrite the snapshot index (`index-N`) file; reads return stale data. Most commonly seen after operators register a new repository to debug an issue with the old one and never delete the old reference.

**Remediation:** Identify the duplicate via GET _snapshot/_all; delete the unused repository:
  DELETE _snapshot/<old-name>
Verify via test snapshot create + restore.

---

### CTL.OPENSEARCH.SNAPSHOT.REPO.ROLE.TRUST.001

**OpenSearch Snapshot Repository Role Lacks OS Service Trust**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.5.16, A.8.13; nist_800_53_r5: CP-9, AC-3; soc2: CC7.4, A1.2;

OpenSearch domain manual-snapshot repository's IAM role's trust policy does not include `es.amazonaws.com` (or `opensearchservice.amazonaws.com` in newer consoles) as a trusted service. Snapshot calls fail with assume-role error; existing snapshots cannot be restored. Common after account-migration / role re-creation when trust list was incomplete.

**Remediation:** Add es.amazonaws.com (or opensearchservice.amazonaws.com) to the role's AssumeRolePolicyDocument. Note: OpenSearch manual snapshots ignore aws:SourceArn and aws:SourceAccount conditions — scope the role's permissions policy to the specific domain ARN instead.

---

### CTL.OPENSEARCH.SNAPSHOT.RETENTION.SHORT.001

**OpenSearch Automated Snapshot Retention Below Compliance Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; hipaa: 164.308(a)(7); iso_27001_2022: A.8.13; nist_800_53_r5: CP-9, AU-11; pci_dss_v4.0: 12.10.5; soc2: CC7.4, A1.2;

OpenSearch automated snapshot retention is at the AWS default (14 days) on a domain scoped for HIPAA, PCI, or SOX compliance. Compliance frameworks specify backup retention windows much longer than 14 days. Recovery from a ransomware / corruption event 30+ days back fails at the snapshot layer.

**Remediation:** Configure manual snapshots to S3 with bucket-level retention matching compliance requirement. Automated snapshots cap at 14d; augment with scheduled manual to long- retention bucket.

---

### CTL.OPENSEARCH.SNAPSHOT.SECURITY.INDEX.MIXED.001

**OpenSearch All-Indices Snapshot Includes Security Index Without Separation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.8.13, A.5.16; nist_800_53_r5: CP-9, IA-5; soc2: CC6.1, CC8.1;

OpenSearch snapshot policy uses an "all indices" pattern that includes `.opendistro_security` (or `.opendistro_security_*`) without separating it into its own snapshot stream. Security index contains FGAC users / role mappings; restoring to a different cluster brings source-cluster identities, which may not exist on the target cluster, leading to authorization failures. Plus the index can contain hashed credentials that should not co-mingle with workload-data backups.

**Remediation:** Split snapshot policies: workload-data snapshots use `*,-.opendistro_security*` pattern; security-state snapshots run separately to a dedicated, more restricted bucket.

---

### CTL.OPENSEARCH.SNAPSHOT.UNAUTHORIZED.REGION.001

**OpenSearch Snapshot Cross-Region Replication In Unauthorized Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.310(d); iso_27001_2022: A.5.10, A.8.13; nist_800_53_r5: AC-3, CA-7; pci_dss_v4.0: 12.10.1; soc2: CC1.5, CC6.1;

OpenSearch snapshot S3 cross-region replication destination is a region not on the org's authorized list. Same data-residency violation as primary domain in unauthorized region — but via the backup path. Backup data is identical to primary; the destination region matters as much as the primary.

**Remediation:** Reconfigure CRR to authorized region. Delete existing replica copies that live in the unauthorized region.

---

### CTL.OPENSEARCH.SNAPSHOT.WINDOW.PEAK.001

**OpenSearch Automated Snapshot Window In Production Peak Hours**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-9; iso_27001_2022: A.5.30, A.8.13; nist_800_53_r5: CP-9, CM-3; soc2: CC8.1, A1.1;

OpenSearch domain's automated snapshot hour falls within the production peak traffic window. Snapshot operations consume IO and JVM resources; running them during peak adds latency to user-facing queries / writes. Default `automated_snapshot_start_hour: 0` (UTC) often falls during US business hours for US-West / US-East workloads.

**Remediation:** Set automated_snapshot_start_hour to off-peak UTC hour matching the workload's traffic pattern. Verify with describe-domain-config.

---

### CTL.OPENSEARCH.SOFTWARE.UPDATE.NOTIFY.001

**OpenSearch Service Software Update Events Not Subscribed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.16, A.8.32; nist_800_53_r5: SI-2, AU-12; soc2: CC7.2, CC8.1;

OpenSearch domain has no EventBridge rule subscribed to `aws.opensearch` / `ServiceSoftwareUpdate` events. Service software updates appear in the AWS Health dashboard but unless wired to a notification channel, operators don't see them until the update becomes mandatory or causes a maintenance- window outage.

**Remediation:** Create EventBridge rule: source aws.opensearch, detail-type "AWS Service Event"; route to SNS / Slack / PagerDuty depending on severity. Subscribe on-call.

---

### CTL.OPENSEARCH.SOFTWARE.UPDATE.STALE.001

**OpenSearch Service Software Update Available For Over 30 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2; iso_27001_2022: A.8.8; nist_800_53_r5: SI-2; pci_dss_v4.0: 6.2; soc2: CC7.1, CC8.1;

OpenSearch domain has an available service software update that has been pending for more than 30 days. AWS publishes updates fixing security and stability issues; ignoring them past the 30-day window indicates patch cadence is not being maintained.

**Remediation:** Apply via StartServiceSoftwareUpdate during next maintenance window. Establish a 7-day SLO for non-critical, 24-hour SLO for security updates.

---

### CTL.OPENSEARCH.STORAGE.NOAUTOSCALE.001

**OpenSearch Domain Has No Storage Auto-Scaling**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: CP-2; iso_27001_2022: A.8.14; nist_800_53_r5: CP-2, SC-5; soc2: A1.1, A1.2;

OpenSearch domain has no storage auto-scaling enabled. Storage growth (logs ingest spike, ISM backlog, snapshot accumulation) hits the EBS volume cap; cluster goes read-only at flood-stage watermark. Manual EBS expansion takes blue-green deployment time during which writes fail.

**Remediation:** Enable via UpdateDomainConfig --advanced-options auto-tune-options. Pair with Free-Storage alarms; auto-scale handles slow growth, alarms catch sudden spikes.

---

### CTL.OPENSEARCH.TIERING.OFF.001

**OpenSearch Domain Has Hot-Warm-Cold Tiering Available But Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** capacity
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.14; nist_800_53_r5: CM-7; soc2: CC8.1;

OpenSearch domain has UltraWarm / Cold storage tiers available (engine + instance class permits) but disabled. Time-series workload (logs, metrics) on hot tier alone costs 3-10x what tiered storage costs. Cold tier is appropriate for indices > 90 days; UltraWarm for 14-90 days; hot for < 14 days.

**Remediation:** Enable UltraWarm and / or Cold tier; create ISM policy to migrate indices age-by-age. Cost optimization: cold storage ~10x cheaper than hot.

---

### CTL.OPENSEARCH.TLS.POLICY.WEAK.001

**OpenSearch Domain TLS Policy Below Modern Floor**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-8, SC-13; iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.2.1, A2.1; soc2: CC6.7;

OpenSearch domain's `tls_security_policy` is below `Policy-Min-TLS-1.2-PFS-2023-10`. Older policies (`Policy-Min-TLS-1.0-2019-07`, `Policy-Min-TLS-1.2-2019-07`) permit TLS 1.0 / 1.1 negotiation and / or non-PFS cipher suites. PCI-DSS v4.0 requires TLS 1.2+, NIST guidance deprecates TLS 1.0/1.1 entirely, and modern browsers / clients have already removed support. Domains created before late 2023 commonly carry the older default and are never updated.

**Remediation:** Update the domain to the modern policy:
  aws es update-domain-config
    --domain-name <name>
    --domain-endpoint-options '{
      "TLSSecurityPolicy":
        "Policy-Min-TLS-1.2-PFS-2023-10"
    }'
Verify with describe-domain-config; the change is blue-green and may take ~30 min on large domains.

---

### CTL.OPENSEARCH.VPC.001

**Domain Must Be Deployed in VPC**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

OpenSearch domains must be deployed within a VPC, not on public endpoints. A domain outside a VPC is directly reachable from the internet, bypassing all network-level controls. Even with authentication enabled, a public endpoint exposes the cluster to brute-force, credential stuffing, and zero-day exploits. VPC deployment restricts access to authorized networks only.

**Remediation:** Create a new domain with VPC configuration specifying private subnets and security groups. Migrate data from the public domain. Use VPN, bastion host, or AWS PrivateLink for authorized access. Note: existing domains cannot be migrated to VPC in-place.

---

### CTL.OPENSEARCH.VPCE.FOREIGN.PRINCIPAL.001

**OpenSearch VPC Endpoint Service Permits Foreign AWS Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.20, A.8.22; nist_800_53_r5: SC-7, AC-4; pci_dss_v4.0: 1.3.4; soc2: CC6.1, CC6.6;

OpenSearch domain's PrivateLink-style VPC endpoint service permits principals outside the domain's organization or trusted-account list. The endpoint service is a network-level grant — once a foreign account creates a VPC endpoint to it, traffic from that account's VPC reaches the domain regardless of the resource policy's `Principal` clause. The endpoint service ACL must enumerate only known trusted account IDs.

**Remediation:** Restrict the endpoint service ACL to the trusted account list:
  aws ec2 modify-vpc-endpoint-service-permissions
    --service-id <id>
    --remove-allowed-principals <foreign-account-arns>
Audit periodically; foreign-account ARNs added for one-off integrations get left behind.

---


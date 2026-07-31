# Control Reference — NEPTUNE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.NEPTUNE.AUDIT.PARAM.OFF.001

**Neptune Audit Log Cluster Parameter Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Neptune clusters must have the `neptune_enable_audit_log` cluster parameter set to 1 so authentication, authorization, and query events are produced by the engine. Distinct from CTL.NEPTUNE.LOG.AUDIT.001 (CloudWatch export): if the parameter is 0, no audit events are produced in the first place and the CloudWatch exporter has nothing to forward — the operator sees CWL log groups but they remain empty until something actually generates events.

**Remediation:** Update the cluster parameter group so `neptune_enable_audit_log=1` and apply the change. Verify CTL.NEPTUNE.LOG.AUDIT.001 (CloudWatch export) is also satisfied — both are required for an end-to-end audit trail.

---

### CTL.NEPTUNE.AUTH.IAM.001

**Neptune Must Enable IAM Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2; soc2: CC6.1;

Neptune clusters must enable IAM database authentication.

**Remediation:** Enable IAM authentication on the cluster.

---

### CTL.NEPTUNE.BACKUP.001

**Neptune Automated Backups Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

Neptune clusters must have automated backups with adequate retention.

**Remediation:** Set backup retention period to at least 7 days.

---

### CTL.NEPTUNE.DELETEPROT.001

**Neptune Must Have Deletion Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

Neptune clusters must have deletion protection enabled.

**Remediation:** Enable deletion protection on the cluster.

---

### CTL.NEPTUNE.ENCRYPT.KMS.AWSMANAGED.001

**Neptune Cluster Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Neptune clusters must encrypt at rest with a customer-managed KMS key, not the AWS-managed `aws/rds` default. The AWS-managed key is shared across every RDS-family cluster in the account, has a key policy the customer cannot edit, and cannot be revoked or rotated on the customer's schedule. Using it satisfies the at-rest encryption checkbox but eliminates the per-tenant key-policy and per-incident key-revocation controls that customer-managed keys provide.

**Remediation:** Create a customer-managed KMS key with a scoped key policy and re-encrypt the cluster (requires a snapshot restore to a new cluster pointed at the customer-managed key). Rotate any snapshot copy grants to use the same CMK.

---

### CTL.NEPTUNE.ENCRYPT.KMS.CROSSACCOUNT.001

**Neptune Cluster KMS Key Must Not Permit Cross-Org Decrypt**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 3.6.1; soc2: CC6.6;

The KMS key encrypting a Neptune cluster (and its snapshots) must not have a key policy granting `kms:Decrypt` to principals outside the organization's allow-list. A snapshot copy encrypted with such a key is decryptable wherever those principals reach — turning a cross-account snapshot share into a clear-text exfil path. Especially material for graph workloads since a single Neptune snapshot typically captures the relationships between *every* identity / asset / policy the organization tracks.

**Remediation:** Tighten the key policy: scope `kms:Decrypt` to specific `aws:PrincipalOrgID` or explicit account ARNs that legitimately need to read the encrypted data, and add `aws:ViaService = rds.<region>.amazonaws.com` so the grant only applies through the Neptune integration path.

---

### CTL.NEPTUNE.ENCRYPT.REST.001

**Neptune Clusters Must Have Encryption at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Neptune clusters must encrypt data at rest with KMS.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster.

---

### CTL.NEPTUNE.ENGINE.EOL.001

**Neptune Engine Version Must Not Be End-of-Life**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Neptune clusters must not run engine versions that have reached end-of-life. AWS publishes a deprecation calendar per Neptune engine version; clusters on a deprecated version no longer receive security patches and will eventually be force-upgraded during a maintenance window the operator did not choose. This is distinct from CTL.NEPTUNE.UPGRADE.001 which checks the auto-minor-upgrade toggle — auto-upgrade applies patches within a supported major version but does not upgrade between major versions. A cluster with auto-upgrade enabled on an EOL major version receives no further patches. The same lifecycle pattern as CTL.DOCUMENTDB.ENGINE.DEPRECATED.001 and CTL.RDS.ENGINE.EOL.001.

**Remediation:** Upgrade the cluster to a supported engine version using aws neptune modify-db-cluster --engine-version <ver> --apply-immediately. Coordinate the upgrade with application teams — major version upgrades may change Gremlin or SPARQL query behavior.

---

### CTL.NEPTUNE.GLOBAL.ENCRYPT.MISMATCH.001

**Global Database Replicas Have Inconsistent Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Neptune Global Database has secondary clusters in regions with different encryption configurations than the primary. If the primary uses a customer-managed KMS key and a secondary does not, the same graph data has different protection levels across regions. The weakest secondary's encryption level is the effective protection for the replicated data set.

**Remediation:** Remove and re-add secondary clusters with KMS keys at the same tier as the primary. Each region's key must exist in that region.

---

### CTL.NEPTUNE.LOADER.ROLE.CROSSBUCKET.001

**Neptune Loader Role Must Stay Inside the Bucket Allow-List**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM role attached to a Neptune cluster's `LOADER` feature must permit only the buckets explicitly registered in the organization's data-source allow-list. Even when the role does not use a wildcard resource, granting access to buckets outside the curated list (a former data partner, a stale staging bucket) lets a Gremlin/SPARQL execute principal pivot the loader into clear-text reads against data the warehouse has no business touching. The control is the cross-bucket complement to LOADER.ROLE.WILDCARD.001 — that one catches `s3:*`; this one catches narrowly scoped roles that drift outside the allow-list.

**Remediation:** Inventory the role's S3 statements against the allow-list and remove each unauthorized bucket ARN. If the bucket genuinely needs to be a Neptune data source, register it in the allow- list first so the deviation does not return on the next audit.

---

### CTL.NEPTUNE.LOADER.ROLE.WILDCARD.001

**Neptune Loader IAM Role Must Not Use Wildcard S3 Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.5; soc2: CC6.3;

An IAM role attached to a Neptune cluster's `LOADER` feature must not grant `s3:*` or `Resource: "*"` on any S3 statement. The loader role is assumed by the cluster when an operator runs `loader` against an S3 source — any database principal with Gremlin/SPARQL execute can issue that load call, so a role with wildcard S3 access turns graph-query execute into arbitrary- bucket *write* (the loader can also stage transformed data back to S3) and exfiltration vector.

**Remediation:** Replace `Resource: "*"` with explicit bucket ARNs the cluster legitimately ingests data from. Split read and write into separate roles when the data sources differ, and limit the `LOADER` association to the read-only role.

---

### CTL.NEPTUNE.LOG.AUDIT.001

**Neptune Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Neptune clusters must export audit logs to CloudWatch Logs.

**Remediation:** Enable CloudWatch log export on the cluster.

---

### CTL.NEPTUNE.MULTIAZ.001

**Neptune Clusters Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

Neptune clusters must deploy across multiple availability zones.

**Remediation:** Add read replicas in additional availability zones.

---

### CTL.NEPTUNE.QUERY.LOG.OFF.001

**Neptune Slow-Query Log Must Be Enabled in Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.5; soc2: CC7.2;

Neptune clusters in production should have the `neptune_query_log_mode` cluster parameter set to a recording mode (e.g. `enabledForAllQueries` or `enabledForSlowQueriesOnly`). Without slow-query logging, the audit log records that a query happened but not what it queried — post-incident "what data did the attacker traverse?" reduces to "every node and edge the compromised principal could reach", which on a graph workload is typically the entire organizational map.

**Remediation:** Update the cluster parameter group so `neptune_query_log_mode=enabledForSlowQueriesOnly` and set `neptune_query_log_slow_query_threshold` to a value matching the team's slow-query baseline. Pair with CTL.NEPTUNE.LOG.AUDIT.001 so the query log reaches CloudWatch.

---

### CTL.NEPTUNE.SG.OPEN.001

**Neptune Cluster Security Group Must Not Allow 0.0.0.0/0 Ingress on 8182**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

Neptune clusters must not have a VPC security group attached that allows 0.0.0.0/0 ingress on the Gremlin / SPARQL endpoint port (8182). Distinct from CTL.NEPTUNE.SUBNET.PUBLIC.001 (subnet placement): even with the cluster in a private subnet, an open security group plus a transit gateway peer or misconfigured NAT exposes the graph endpoint to internet scanners. Neptune has no database-local password — IAM auth is the only auth mechanism — so the security boundary is entirely the network policy plus CTL.NEPTUNE.AUTH.IAM.001.

**Remediation:** Replace the 0.0.0.0/0 rule with the CIDR block(s) of the application tier or VPN range that legitimately needs cluster access. Even in private deployments, scope the rule to the specific tier rather than the whole VPC.

---

### CTL.NEPTUNE.SNAPSHOT.ENCRYPT.001

**Neptune Snapshots Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Neptune cluster snapshots must be encrypted.

**Remediation:** Copy snapshots with encryption enabled.

---

### CTL.NEPTUNE.SNAPSHOT.PUBLIC.001

**Neptune Snapshots Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

Neptune snapshots must not be publicly accessible.

**Remediation:** Remove public access from the snapshot.

---

### CTL.NEPTUNE.SNAPSHOT.SHARED.CROSSACCOUNT.001

**Neptune Snapshots Must Not Be Shared With Out-of-Org Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.5; soc2: CC6.6;

A Neptune manual snapshot must not be shared with AWS account IDs outside the organization's snapshot-sharing allow-list. Snapshot sharing is the legitimate cross-account graph handoff mechanism — but the failure mode is sharing with an account that used to be a partner, has been compromised, or was never authorized. Once shared, the recipient can restore the graph in their own VPC and traverse every relationship the snapshot captured. Distinct from CTL.NEPTUNE.SNAPSHOT.PUBLIC.001 (which catches `all`); this one catches specific out-of-org account IDs.

**Remediation:** Revoke each unauthorized account's restore access: `aws neptune modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier <id> --attribute-name restore --values-to-remove <acct>`. If cross-account sharing is genuinely required, register the target account in the allow-list first.

---

### CTL.NEPTUNE.STREAMS.UNINTENDED.001

**Neptune Streams Must Have a Bounded Consumer Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

When `neptune_streams=1` is enabled at the cluster parameter group, the cluster exposes a change-feed endpoint that any in-VPC consumer can poll. Streams are intentional for some pipelines (Lambda subscribers, ETL into a search index) but unintentional exposure is the failure mode: the parameter is toggled on for a one-off integration and never paired with a bounded consumer-policy registry, so any newly-deployed workload in the VPC can subscribe to the stream and receive every mutation. The control fires when streams are on and the registered consumer-policy list is empty.

**Remediation:** Register the legitimate stream consumers (Lambda ARNs, EC2 role ARNs) in the cluster's stream consumer-policy list. If no consumer is currently using the stream, set `neptune_streams=0` until a real subscriber arrives.

---

### CTL.NEPTUNE.SUBNET.PUBLIC.001

**Neptune Must Not Use Public Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Neptune clusters must not be deployed in public subnets.

**Remediation:** Move the cluster to private subnets.

---

### CTL.NEPTUNE.UPGRADE.001

**Neptune Must Enable Auto Minor Version Upgrade**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

Neptune instances must enable automatic minor version upgrades.

**Remediation:** Enable auto minor version upgrade.

---


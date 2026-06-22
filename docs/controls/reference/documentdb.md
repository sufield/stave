# Control Reference — DOCUMENTDB

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DOCUMENTDB.AUDIT.PARAM.OFF.001

**DocumentDB Audit Log Parameter Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

DocumentDB clusters must have the `audit_logs` cluster parameter set to `enabled` so authentication, authorization, and CRUD events are recorded by the engine. Distinct from the existing CTL.DOCUMENTDB.LOG.AUDIT.001 — which checks the *export* of audit logs to CloudWatch — this control catches the upstream gap where no audit events are produced in the first place. With `audit_logs=disabled`, the CWL exporter receives nothing and the forensic trail is empty even though the operator believes audit logging is "on".

**Remediation:** Update the cluster parameter group so `audit_logs=enabled` and apply the change. Verify CTL.DOCUMENTDB.LOG.AUDIT.001 (CloudWatch export) is also satisfied — both are needed for an end-to-end audit trail.

---

### CTL.DOCUMENTDB.BACKUP.001

**DocumentDB Automated Backups Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

DocumentDB clusters must have automated backups.

**Remediation:** Set backup retention period to at least 7 days.

---

### CTL.DOCUMENTDB.CONFIG.ADMIN.001

**DocumentDB Must Not Use a Default Admin Username**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5;

DocumentDB clusters must not be configured with a guessable default master username (`admin`, `docdb`, `root`, `administrator`, `superuser`). The master username appears in every connection string and CloudTrail event, and credential- stuffing tools test the well-known defaults first. Picking a non-default username eliminates the easiest enumeration path and forces an attacker to harvest the username separately before any password attempt becomes useful.

**Remediation:** Provision a new cluster with a non-default master username (e.g. `svc_<team>_admin`) and migrate. The master username cannot be renamed in place; replacement requires a snapshot-restore-and-cutover rotation.

---

### CTL.DOCUMENTDB.DELETEPROT.001

**DocumentDB Must Have Deletion Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-10; soc2: CC6.1;

DocumentDB clusters must have deletion protection enabled.

**Remediation:** Enable deletion protection.

---

### CTL.DOCUMENTDB.ENCRYPT.KMS.AWSMANAGED.001

**DocumentDB Cluster Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

DocumentDB clusters must encrypt at rest with a customer-managed KMS key, not the AWS-managed `aws/rds` default. The AWS-managed key is shared across every RDS-family cluster in the account, has a key policy the customer cannot edit, and cannot be revoked or rotated on the customer's schedule. Using it satisfies the at-rest encryption checkbox but eliminates the per-tenant key-policy and per-incident key-revocation controls customer- managed keys provide.

**Remediation:** Create a customer-managed KMS key with a scoped key policy, then re-encrypt the cluster (requires a snapshot restore to a new cluster pointed at the customer-managed key). Rotate any cross-region snapshot copy grants to use the same CMK.

---

### CTL.DOCUMENTDB.ENCRYPT.KMS.CROSSACCOUNT.001

**DocumentDB Cluster KMS Key Must Not Permit Cross-Org Decrypt**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 3.6.1; soc2: CC6.6;

The KMS key encrypting a DocumentDB cluster (and its snapshots) must not have a key policy that grants `kms:Decrypt` to principals outside the organization's allow-list. A snapshot copy encrypted with such a key is decryptable wherever those principals reach — turning a cross-account snapshot share into a clear-text exfil path even when storage encryption is on and snapshot sharing is restricted, because the recipient still legitimately holds Decrypt against the source key.

**Remediation:** Tighten the key policy: scope `kms:Decrypt` to specific `aws:PrincipalOrgID` or explicit account ARNs that legitimately need to read the encrypted data, and add `aws:ViaService = rds.<region>.amazonaws.com` so the grant only applies through the DocDB integration path.

---

### CTL.DOCUMENTDB.ENCRYPT.REST.001

**DocumentDB Clusters Must Have Encryption at Rest**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

DocumentDB clusters must encrypt data at rest.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster.

---

### CTL.DOCUMENTDB.ENGINE.DEPRECATED.001

**DocumentDB Engine Version Must Not Be End-of-Life**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

DocumentDB clusters must run an engine version that AWS still supports — not one on the end-of-life list. AWS publishes a deprecation calendar per engine major version; clusters left on a deprecated version no longer receive security patches and will eventually be force-upgraded by AWS during a maintenance window the operator did not choose. The same scenario as CTL.REDSHIFT.MAINTENANCE.DEFERRED.001 / CTL.REDSHIFT.UPGRADE.001 but for the document store.

**Remediation:** Upgrade the cluster to a supported major version with `aws docdb modify-db-cluster --engine-version <ver> --apply-immediately`. Coordinate the upgrade window with application teams — major-version upgrades can require driver updates on the client side.

---

### CTL.DOCUMENTDB.IAM.AUTH.OFF.001

**DocumentDB Cluster Must Permit IAM Database Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-2; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

DocumentDB clusters must have IAM database authentication enabled so human and service principals authenticate with short-lived IAM-derived credentials instead of long-lived database-local passwords. AWS added IAM auth to DocumentDB after the engine had already been in production for years — most existing clusters still rely exclusively on the master password and any rotated-in application user, leaving no IAM-side audit trail tying a connection to a human identity.

**Remediation:** Modify the cluster with `--enable-iam-database-authentication`. Create dbuser entries that authenticate via IAM, attach `rds-db:connect` IAM policies to the human / service principals that need access, and rotate the existing database-local passwords out.

---

### CTL.DOCUMENTDB.INSTANCE.PUBLIC.001

**DocumentDB Instances Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

No member instance of a DocumentDB cluster may have `publicly_accessible=true`. The cluster-level connection string routes to whichever member is the current writer; even one publicly accessible member exposes the document store to internet scanners. Distinct from CTL.DOCUMENTDB.SG.OPEN.001 (which catches the security-group dimension): this control catches the per-instance flag that drives DNS / public IP assignment regardless of SG configuration.

**Remediation:** Modify each affected member instance with `--no-publicly-accessible`. Per-instance changes apply during the next maintenance window — schedule outside business hours so the brief failover is invisible.

---

### CTL.DOCUMENTDB.LOG.AUDIT.001

**DocumentDB Must Export Logs to CloudWatch**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

DocumentDB clusters must export audit logs to CloudWatch.

**Remediation:** Enable CloudWatch log export.

---

### CTL.DOCUMENTDB.MULTIAZ.001

**DocumentDB Must Use Multi-AZ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: CC7.1;

DocumentDB clusters must deploy across multiple availability zones.

**Remediation:** Add read replicas in additional AZs.

---

### CTL.DOCUMENTDB.PI.OFF.001

**DocumentDB Performance Insights Should Be Enabled in Production**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.2;

Production DocumentDB clusters should enable Performance Insights so per-query wait-state and load-by-wait data are retained for post-incident analysis. PI captures information that the audit log and profiler do not — specifically, which wait events dominated during an outage or query saturation episode. Without PI, root-cause analysis of a slowdown reduces to "the cluster was slow then it wasn't" because the underlying wait-state data was never recorded.

**Remediation:** Enable Performance Insights: `aws docdb modify-db-instance --enable-performance-insights` on each member instance. Default retention is 7 days; extend to 731 days if the operator wants long-baseline trend data.

---

### CTL.DOCUMENTDB.PROFILER.OFF.001

**DocumentDB Profiler Must Be Enabled in Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.5; soc2: CC7.2;

DocumentDB clusters in production should have the `profiler` cluster parameter enabled so slow-query operations are captured alongside the audit log. The profiler is the only mechanism that records query *shape* (collection, predicate fields, sort order) for queries that exceed the profiling threshold — without it, a post-incident question of "what did the attacker query?" is unanswerable because the audit log only records the operation category, not the query body.

**Remediation:** Update the cluster parameter group so `profiler=enabled`, set `profiler_threshold_ms` to a value matching the team's slow-query baseline (typically 100–500 ms), and apply the change. Pair with `LOG.AUDIT.001` so the profiler output reaches CloudWatch.

---

### CTL.DOCUMENTDB.SG.OPEN.001

**DocumentDB Cluster Security Group Must Not Allow 0.0.0.0/0 Ingress on 27017**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

DocumentDB clusters must not have a VPC security group attached that allows 0.0.0.0/0 ingress on the cluster port (27017). Even with member instances configured `publicly_accessible=false`, an open security group on a cluster placed in a public subnet — or reachable through a misconfigured NAT / transit gateway — exposes the document store to internet scanners. Distinct from CTL.DOCUMENTDB.SNAPSHOT.PUBLIC.001 (snapshot share) and CTL.DOCUMENTDB.INSTANCE.PUBLIC.001 (instance flag): this control catches the network-policy gap that admits the wrong source even when the per-instance flag is correct.

**Remediation:** Replace the 0.0.0.0/0 rule with the CIDR block(s) of the application tier or VPN range that legitimately needs cluster access. Avoid scoping rules to "any private RFC1918" — that admits the entire VPC's compute fleet.

---

### CTL.DOCUMENTDB.SNAPSHOT.PUBLIC.001

**DocumentDB Snapshots Must Not Be Public**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

DocumentDB snapshots must not be publicly accessible.

**Remediation:** Remove public access from the snapshot.

---

### CTL.DOCUMENTDB.SNAPSHOT.SHARED.CROSSACCOUNT.001

**DocumentDB Snapshots Must Not Be Shared With Out-of-Org Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.5; soc2: CC6.6;

A DocumentDB manual snapshot must not be shared with AWS account IDs outside the organization's snapshot-sharing allow-list. Snapshot sharing is the legitimate cross-account data-handoff mechanism for DocDB — but the failure mode is sharing with an account that used to be a partner, has been compromised, or was never authorized. Once shared, the recipient can restore at any time, typically months after the share was set up and forgotten. Distinct from CTL.DOCUMENTDB.SNAPSHOT.PUBLIC.001 (which catches `all`); this one catches specific out-of-org account IDs.

**Remediation:** Revoke each unauthorized account's restore access: `aws docdb modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier <id> --attribute-name restore --values-to-remove <acct>`. If cross-account sharing is genuinely required, register the target account in the allow-list first.

---

### CTL.DOCUMENTDB.TLS.DISABLED.001

**DocumentDB Cluster Must Require TLS**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

DocumentDB clusters must have the `tls` cluster parameter set to `enabled` so connections without TLS are rejected. The pre-2024 default for newly created clusters used `disabled`, and many long-lived production clusters still inherit that setting through custom parameter groups copied from the original default. With TLS off, MongoDB-wire-protocol authentication frames (including the SCRAM challenge/response) traverse the VPC in clear and any in-VPC packet capture recovers the cluster's master credentials.

**Remediation:** Update (or replace) the cluster parameter group so `tls=enabled`, associate it with the cluster, and apply the change immediately (`ApplyImmediately=true`). Drivers connecting without `tls=true` / `ssl=true` will then fail closed instead of falling back to clear text.

---


# Control Reference — REDSHIFT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.REDSHIFT.AUDIT.LOGDESTINATION.001

**Redshift Audit Log Destination Must Be Bucket-Hardened**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-9; pci_dss_v4.0: 10.3.1; soc2: CC7.2;

When Redshift audit logging is configured to deliver to S3 (`logging.log_destination_type=s3`), the destination bucket must itself be hardened: a bucket policy restricting writes to the Redshift service principal, a deny-without-MFA policy on delete, and a configured lifecycle policy. A misconfigured destination bucket means audit logs land in storage anyone can delete or overwrite — turning the audit trail into something an attacker reaches *as part of* covering their tracks. The control is paired with CTL.REDSHIFT.LOG.AUDIT.001 (which only asserts logging is on); this one asserts where logging lands is itself defended.

**Remediation:** Update the destination bucket: add a bucket policy granting PutObject only to `redshift.amazonaws.com`, deny `s3:Delete*` without MFA, configure a lifecycle policy aligned with the organization's retention requirement, and enable bucket-level Object Lock if the framework demands write-once retention.

---

### CTL.REDSHIFT.BACKUP.001

**Redshift Automated Snapshots Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: CC7.1;

Redshift clusters must have automated snapshots enabled with adequate retention.

**Remediation:** Set automated snapshot retention period to at least 7 days.

---

### CTL.REDSHIFT.CONFIG.ADMIN.001

**Redshift Must Not Use Default Admin Username**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5;

Redshift clusters must not use the default admin username (awsuser).

**Remediation:** Create a new cluster with a non-default admin username.

---

### CTL.REDSHIFT.CONFIG.DBNAME.001

**Redshift Must Not Use Default Database Name**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

Redshift clusters should not use the default database name (dev).

**Remediation:** Create a new cluster with a descriptive database name.

---

### CTL.REDSHIFT.DATASHARE.CROSSACCOUNT.UNAUTHORIZED.001

**Redshift Datashare Consumers Must Stay Inside the Allow-List**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.5; soc2: CC6.6;

Each cross-account consumer associated with a Redshift datashare must be in the organization's datashare allow-list. Datashare is a legitimate cross-account data-handoff mechanism, but the failure mode is a former partner / acquired-and-divested business unit / one-off project consumer that was never removed from the producer's datashare. Once associated, the consumer account can query the producer's tables in place — no snapshot copy, no audit on the producer side beyond the initial share — for as long as the association persists. The control is the cross-account sibling of CTL.REDSHIFT.DATASHARE.PUBLIC.001: that one catches `AllowPubliclyAccessibleConsumers=true`; this one catches consumer ARNs that drift outside the allow-list.

**Remediation:** Disassociate each unauthorized consumer: `aws redshift disassociate-data-share-consumer --data-share-arn <arn> --consumer-arn <arn>`. If a consumer is genuinely still authorized, register them in the allow-list first so the deviation does not return on the next audit.

---

### CTL.REDSHIFT.DATASHARE.PUBLIC.001

**Redshift Datashare Must Not Allow Publicly Accessible Consumers**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S08; pci_dss_v4.0: 1.3.4; soc2: CC6.6; subtractive_tier: deletion;

Redshift datashares can be created with `AllowPubliclyAccessibleConsumers=true` — a setting that permits a datashare to be consumed by clusters whose `PubliclyAccessible` flag is set. Combining a datashare with public consumers effectively re-exports warehouse data to any internet-reachable cluster the consumer account creates, bypassing the producer's network controls entirely. This is distinct from the cross-account share check: a cross-account share to a trusted partner is fine, but allowing that partner to consume from a public-facing cluster reintroduces the exposure the producer's PUBLIC.001 control was preventing.

**Remediation:** Update the datashare with `aws redshift modify-data-share --data-share-arn <arn> --no-allow-publicly-accessible-consumers`. Audit any consumer cluster ARNs to confirm none are themselves publicly accessible.

---

### CTL.REDSHIFT.ENCRYPT.KMS.AWSMANAGED.001

**Redshift Cluster Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Redshift clusters must encrypt at rest with a customer-managed KMS key, not the AWS-managed `aws/redshift` default. The AWS-managed key is shared across every Redshift cluster in the account, has a key policy the customer cannot edit, and cannot be revoked or rotated on the customer's schedule. Using it satisfies the at-rest encryption checkbox but eliminates the per-tenant key-policy and per-incident key-revocation controls that customer-managed keys provide.

**Remediation:** Create a customer-managed KMS key with a scoped key policy, then re-encrypt the cluster (requires a snapshot restore to a new cluster pointed at the customer-managed key). Update the snapshot copy grants to use the same CMK.

---

### CTL.REDSHIFT.ENCRYPT.KMS.CROSSACCOUNT.001

**Redshift Cluster KMS Key Must Not Permit Cross-Org Decrypt**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 3.6.1; soc2: CC6.6;

The KMS key encrypting a Redshift cluster (and its automated / manual snapshots, plus any cross-region copies via the snapshot copy grant) must not have a key policy granting `kms:Decrypt` to principals outside the organization's allow-list. A snapshot copy encrypted with such a key is decryptable wherever those principals reach — turning a cross-account snapshot share into a clear-text exfil path even when storage encryption is "on" and snapshot sharing is restricted, because the recipient still legitimately holds Decrypt against the source key. The combination is the least-visible warehouse exfil pattern: the share looks compliant, the encryption looks compliant, only the key policy breaks containment.

**Remediation:** Tighten the key policy: scope `kms:Decrypt` to specific `aws:PrincipalOrgID` or explicit account ARNs that legitimately need to read the encrypted data, and add `aws:ViaService = redshift.<region>.amazonaws.com` so the grant only applies through the Redshift integration path. Re-issue any cross-region snapshot-copy grants against the tightened key.

---

### CTL.REDSHIFT.ENCRYPT.REST.001

**Redshift Clusters Must Have Encryption at Rest Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Redshift clusters must have encryption at rest enabled with KMS.

**Remediation:** Enable encryption. Requires creating a new encrypted cluster and migrating data.

---

### CTL.REDSHIFT.FIPS.001

**Redshift Cluster Must Use FIPS-Validated SSL When Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_high: SC-13; fedramp_moderate: SC-13; nist_800_53_r5: SC-13; pci_dss_v4.0: 4.2.1;

Redshift clusters subject to FIPS 140-2 / FIPS 140-3 compliance obligations (FedRAMP Moderate / High, DoD IL2+, certain healthcare data residencies) must set `use_fips_ssl=true` in the cluster parameter group so the SSL endpoint serves only FIPS-validated cipher suites. The default `use_fips_ssl=false` permits non-FIPS ciphers and disqualifies the cluster from attestation under those frameworks even when `require_ssl` is enabled.

**Remediation:** Update the cluster parameter group so `use_fips_ssl=true` and apply the change. Verify with `aws redshift describe-cluster-parameters` that the parameter actually applied — Redshift sometimes silently retains the previous value when the parameter group is detached and reattached.

---

### CTL.REDSHIFT.HSM.MISCONFIG.001

**Redshift HSM Encryption Mode Must Match Compliance Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_high: SC-13; nist_800_53_r5: SC-13; pci_dss_v4.0: 3.6.1;

When the organization's compliance profile mandates HSM-backed key custody (FedRAMP High, FIPS 140-2 Level 3, certain financial-services attestations), the Redshift cluster's `hsm_status` must report `active` against the configured HSM client certificate and HSM configuration. The failure mode is silent drift: an HSM-required cluster restored from snapshot without re-attaching the HSM configuration ends up encrypted with a software KMS key — the cluster keeps running, the compliance attestation lapses, and the operator only finds out during the next audit.

**Remediation:** Re-attach the HSM configuration: `aws redshift modify-cluster-iam-roles ... --hsm-client-certificate-identifier <cert> --hsm-configuration-identifier <cfg>` and verify with `describe-clusters` that `HsmStatus.Status` is `active`. If the HSM is no longer needed because the compliance profile changed, document the profile change rather than letting the cluster drift.

---

### CTL.REDSHIFT.IAM.DBAUTH.OFF.001

**Redshift Cluster Must Permit IAM Database Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

Redshift clusters must permit IAM-based database authentication via `GetClusterCredentials` so that human and service principals authenticate with short-lived credentials tied to IAM identity, not with long-lived database-local passwords. A cluster that accepts only DB-local credentials is one shared password rotation away from a credential-stuffing incident, and offers no audit trail back to a human IAM user.

**Remediation:** Create an IAM policy granting `redshift:GetClusterCredentials` scoped to the specific dbuser/dbgroup on this cluster, attach it to the human/service principals that need warehouse access, and rotate the existing database-local passwords out.

---

### CTL.REDSHIFT.IAM.ROLE.WILDCARD.001

**Redshift Attached IAM Role Must Not Use Wildcard Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.5; soc2: CC6.3;

An IAM role attached to a Redshift cluster (used by COPY, UNLOAD, Redshift Spectrum) must not grant `s3:*` or `Resource: "*"` on any S3 statement. The cluster's role is assumable by anyone with database-level execute on COPY/UNLOAD; an `s3:GetObject` / `s3:PutObject` with `Resource: "*"` turns SQL execute into arbitrary-bucket read/write — a one-step exfiltration pivot.

**Remediation:** Replace `Resource: "*"` with explicit bucket ARNs that the warehouse legitimately ingests from or exports to. Split read and write privileges into separate roles if they target different buckets, and attach roles via cluster IAM role associations rather than via the cluster's primary execution role where possible.

---

### CTL.REDSHIFT.LOG.ACTIVITY.001

**Redshift Must Log User Activity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Redshift user activity logging must be enabled to record SQL statements.

**Remediation:** Enable user activity logging in the parameter group.

---

### CTL.REDSHIFT.LOG.AUDIT.001

**Redshift Clusters Must Have Audit Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

Redshift audit logging must be enabled for connection, user, and query activity.

**Remediation:** Enable audit logging to S3 or CloudWatch.

---

### CTL.REDSHIFT.MAINTENANCE.DEFERRED.001

**Redshift Cluster Must Not Have Maintenance Indefinitely Deferred**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

Redshift exposes a `DeferredMaintenanceWindows` mechanism so operators can postpone an engine patch through an in-flight business window. The mechanism becomes a security failure when a cluster has had maintenance deferred continuously for longer than the maximum supported window — engine CVEs queue up unpatched, and the cluster runs an unsupported version that AWS will eventually force-upgrade in a less convenient window than the one the operator was protecting.

**Remediation:** Schedule a maintenance window outside of business hours, allow the deferred window to expire, then verify with `aws redshift describe-clusters --query 'Clusters[].DeferredMaintenanceWindows'` that no active deferred window remains.

---

### CTL.REDSHIFT.MULTI.AZ.OFF.001

**Redshift RA3 Cluster Should Run Multi-AZ for Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

Production Redshift clusters on the RA3 node family should run with `multi_az=true` so a single Availability Zone outage does not take the warehouse offline. The setting is RA3-only — DC2 / DS2 nodes do not support Multi-AZ — and is opt-in per cluster. Running production warehouses single-AZ is a quiet availability bet: the cluster comes back online when the AZ recovers, but the dependent BI / analytics workload was unavailable for the duration of the outage.

**Remediation:** Modify the cluster with `--multi-az=true`. The conversion is online for RA3 clusters but applies during the next maintenance window — schedule outside business hours so the intermediate brief failover is invisible.

---

### CTL.REDSHIFT.PUBLIC.001

**Redshift Clusters Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S08; pci_dss_v4.0: 1.3.4; soc2: CC6.6; subtractive_tier: deletion;

Redshift clusters must not have the publicly accessible setting enabled.

**Remediation:** Disable public accessibility and place the cluster in a private subnet.

---

### CTL.REDSHIFT.SECRET.PLAIN.001

**Redshift Cluster Must Use Secrets Manager for Master Password**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3; soc2: CC6.1;

Redshift cluster master password is not managed by AWS Secrets Manager. Plaintext passwords in Terraform state, CloudFormation parameters, or environment variables are exposed to anyone with access to the deployment pipeline. Secrets Manager provides automatic rotation and audit logging for database credentials.

**Remediation:** Enable Secrets Manager integration for the Redshift cluster master password. Use manage_master_user_password in Terraform or the ManageMasterUserPassword API parameter.

---

### CTL.REDSHIFT.SG.OPEN.001

**Redshift Cluster Security Group Must Not Allow 0.0.0.0/0 Ingress on 5439**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

Redshift clusters must not have a VPC security group attached that allows 0.0.0.0/0 ingress on the cluster port (5439). Even with PubliclyAccessible=false, an open security group on a cluster placed in a public subnet — or behind a misconfigured NAT / transit gateway — exposes the warehouse to internet scanners. Distinct from CTL.REDSHIFT.PUBLIC.001 which catches the cluster-level flag; this control catches the network-policy gap that leaves the cluster reachable when the flag is off.

**Remediation:** Replace the 0.0.0.0/0 rule with the CIDR block(s) of the application tier or VPN range that legitimately needs cluster access. If the cluster must be accessible from on-premises, scope the rule to the enterprise NAT gateway IPs, not to the public internet.

---

### CTL.REDSHIFT.SNAPSHOT.COPY.UNENCRYPTED.001

**Redshift Cross-Region Snapshot Copies Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

When Redshift cross-region snapshot copying is enabled (`snapshot_copy.destination_region` set), every copy in the destination region must be encrypted with a customer-managed KMS key registered through a snapshot copy grant. Copies that land unencrypted in the destination region defeat the source region's encryption: the snapshot data exists in plaintext on AWS infrastructure, and any account principal with `redshift:RestoreFromClusterSnapshot` in the destination region reads it without ever touching the source key.

**Remediation:** Create a customer-managed KMS key in the destination region, create a snapshot copy grant on it, and re-enable cross-region copying with `--snapshot-copy-grant-name`. Re-copy any in-flight snapshots so the historical chain is also encrypted.

---

### CTL.REDSHIFT.SNAPSHOT.SHARED.CROSSACCOUNT.001

**Redshift Manual Snapshot Must Not Be Shared With Out-of-Org Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.5; soc2: CC6.6;

A Redshift manual snapshot must not be shared with AWS account IDs that are outside the organization's allow-list of trusted accounts. Snapshot sharing is a legitimate cross-account data-handoff mechanism — but the failure mode is sharing with an attacker- controlled or partner account that no longer needs access. Once shared, the recipient account can restore the snapshot and exfil data without ever touching the source VPC.

**Remediation:** Revoke each unauthorized account's restore access: `aws redshift revoke-snapshot-access --snapshot-identifier <id> --account-with-restore-access <acct>`. If cross-account sharing is genuinely required, register the target account in the allow-list and re-share so future audits treat the share as expected.

---

### CTL.REDSHIFT.SNAPSHOT.SHARED.PUBLIC.001

**Redshift Manual Snapshot Must Not Be Shared Publicly**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

A Redshift manual snapshot must not be shared with `all` (every AWS account in the world). A public snapshot is the data-warehouse equivalent of a public S3 bucket: any AWS account can restore the snapshot into their own cluster and read the contents at their leisure. This is the single highest-impact misconfiguration on a warehouse — full historical data egress with no in-VPC log trail.

**Remediation:** Revoke the public share immediately: `aws redshift revoke-snapshot-access --snapshot-identifier <id> --account-with-restore-access all`. Audit CloudTrail for any `RestoreFromClusterSnapshot` calls from accounts outside your organization since the snapshot was created.

---

### CTL.REDSHIFT.SSL.001

**Redshift Clusters Must Require SSL Connections**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Redshift parameter group must set require_ssl to true.

**Remediation:** Set require_ssl=true in the cluster's parameter group.

---

### CTL.REDSHIFT.UPGRADE.001

**Redshift Must Allow Automatic Version Upgrades**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2;

Redshift clusters should have automatic version upgrades enabled.

**Remediation:** Enable AllowVersionUpgrade on the cluster.

---

### CTL.REDSHIFT.VPC.ROUTING.001

**Redshift Must Use Enhanced VPC Routing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Redshift clusters must use enhanced VPC routing to force all COPY and UNLOAD traffic through the VPC.

**Remediation:** Enable enhanced VPC routing on the cluster.

---

### CTL.REDSHIFT.WLM.QUERY.LIMIT.001

**Redshift Default WLM Queue Should Have Query Monitoring Rules**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: SC-5; soc2: A1.2;

Production Redshift clusters should have at least one Query Monitoring Rule (QMR) on the default WLM queue. QMRs cap per-query resource consumption — query_execution_time, scan_row_count, return_row_count, query_temp_blocks_to_disk — and abort or log outliers that exceed thresholds. Without any rule, a single malformed query (or a deliberate denial-of-service from a compromised dbuser) can saturate the cluster and starve every other workload until manual intervention. The default queue is the one most callers land in, so a QMR there is the simplest way to bound the worst-case query.

**Remediation:** Add at least one QMR to the default queue via the parameter group's `wlm_json_configuration` — typical baseline: abort queries running >300s, log queries scanning >1B rows, abort queries spilling >50GB to disk. Tune to the workload's actual baseline rather than copying the example values verbatim.

---


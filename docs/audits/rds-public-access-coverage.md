# RDS Public Access and Database Security Coverage Audit

Audited: 2026-04-21 (updated: 2026-04-21)
Request: Tesla RDS public access and database security detection
Catalog: 682 controls (23 dedicated CTL.RDS.* controls)

## Summary

**14 of 15 vectors fully covered.** 1 not covered (RDS Proxy —
low priority, deferred). The catalog has 23 dedicated RDS controls
including the new CTL.RDS.SG.BROAD.001 for security group broad
ingress detection in RDS context. Two
chain definitions compose RDS controls into compound attack paths.
The observation contract defines `aws_rds_instance` and
`aws_rds_cluster` asset types with `database.*` properties.

The partially covered vector (security group broad ingress on
database ports) is addressed by `CTL.EC2.SG.RESTRICTED.PORTS.001`
which detects unrestricted access on database ports (3306, 5432,
1433, 27017) but operates on EC2 security group assets, not
directly on RDS instances. The uncovered vector (RDS Proxy) has
no observation property or control.

## For Tesla: what's ready today

### Controls to enable

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Public access | CTL.RDS.PUBLIC.001 | `publicly_accessible == true` |
| SG broad ingress (RDS context) | CTL.RDS.SG.BROAD.001 | `database.network.has_broad_sg_ingress == true` |
| Database port exposure (SG context) | CTL.EC2.SG.RESTRICTED.PORTS.001 | 0.0.0.0/0 on ports 3306/5432/1433/27017 |
| Missing SSL/TLS | CTL.RDS.SSL.001 | `require_ssl == false` |
| TLS enforcement | CTL.RDS.SSL.ENFORCE.001 | `ssl_enforcement_enabled == false` |
| IAM authentication | CTL.RDS.IAMAUTH.001 | `iam_authentication_enabled == false` |
| Unencrypted storage | CTL.RDS.ENCRYPT.001 | `storage_encrypted == false` |
| Auto minor upgrade | CTL.RDS.AUTOUPGRADE.001, CTL.RDS.MINOR.UPGRADE.001 | `auto_minor_version_upgrade == false` |
| Engine EOL | CTL.RDS.ENGINE.EOL.001 | `engine_version.is_eol == true` |
| Public snapshots | CTL.RDS.SNAPSHOT.PUBLIC.001 | `snapshot.is_public == true` |
| Snapshot encryption | CTL.RDS.SNAPSHOT.ENCRYPT.001 | Unencrypted automated snapshots |
| Snapshot export | CTL.RDS.SNAPSHOT.EXPORT.001 | Unrestricted snapshot export to S3 |
| Missing backups | CTL.RDS.BACKUP.001 | `backup.enabled == false` |
| Deletion protection | CTL.RDS.DELETEPROT.001 | `deletion_protection == false` |
| Cluster deletion protection | CTL.RDS.CLUSTER.DELETION.PROTECT.001 | Aurora cluster deletion protection |
| Enhanced monitoring | CTL.RDS.MONITORING.001 | `enhanced_monitoring_enabled == false` |
| Performance Insights | CTL.RDS.PERFORMANCE.INSIGHTS.001 | Missing Performance Insights + KMS |
| Audit logging | CTL.RDS.LOG.001 | `audit_log_enabled == false` |
| Cluster logging | CTL.RDS.CLUSTER.LOGGING.001 | Aurora log export to CloudWatch |
| Event subscriptions | CTL.RDS.EVENTS.001 | Missing critical event subscriptions |
| Default parameter group | CTL.RDS.PARAM.GROUP.001 | Using default parameter group |
| Multi-AZ | CTL.RDS.MULTIAZ.001 | `multi_az == false` |
| Incomplete data | CTL.RDS.INCOMPLETE.001 | Missing observation data |

### Chain definitions

Enable chain detection for compound risk scoring:

- `rds_public_exposure_path` — PUBLIC.001 + ENCRYPT.001 +
  DELETEPROT.001. Fires when a public RDS instance is also
  unencrypted and unprotected from deletion.
- `eol_database_phi_exposure` — ENGINE.EOL.001 + ENCRYPT.001 +
  PUBLIC.001. Fires when an end-of-life database engine is
  public and unencrypted.

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/rds-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

## Exposure Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | PubliclyAccessible flag | CTL.RDS.PUBLIC.001: `database.access.publicly_accessible == true` | **Full** |
| 2 | SG allows broad ingress | CTL.RDS.SG.BROAD.001 (`database.network.has_broad_sg_ingress == true`), CTL.EC2.SG.RESTRICTED.PORTS.001 (SG-level detection) | **Full** |
| 3 | RDS in public subnet | CTL.RDS.PUBLIC.001 covers PubliclyAccessible (which requires public subnet + IGW route). No dedicated subnet check. | **Full** |
| 4 | Combined exposure | `rds_public_exposure_path` chain: PUBLIC.001 + ENCRYPT.001 + DELETEPROT.001 | **Full** (chain-level) |

### Vector 2 detail: Partial coverage

CTL.EC2.SG.RESTRICTED.PORTS.001 detects unrestricted ingress on
database ports including 3306 (MySQL), 5432 (PostgreSQL), 1433
(SQL Server), and 27017 (MongoDB). However, it operates on
`aws_ec2_security_group` assets, not `aws_rds_instance` assets.
The control fires on the security group, not on the database
instance that uses it. An adopter must correlate SG findings with
RDS instances manually.

A dedicated `CTL.RDS.SG.BROAD.001` checking
`database.security_group.has_broad_ingress` on the RDS instance
asset would provide direct detection.

**Gap classification: Gap B.** Requires observation property
`database.security_group.has_broad_ingress` on RDS instance assets.

## Authentication & Encryption Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 5 | Missing TLS (force_ssl) | CTL.RDS.SSL.001 (`require_ssl == false`), CTL.RDS.SSL.ENFORCE.001 (`ssl_enforcement_enabled == false`) | **Full** |
| 6 | Weak authentication | CTL.RDS.IAMAUTH.001 (`iam_authentication_enabled == false`), CTL.RDS.PARAM.GROUP.001 (default param group) | **Full** |
| 7 | Unencrypted storage | CTL.RDS.ENCRYPT.001 (`storage_encrypted == false`) | **Full** |
| 8 | Missing auto upgrades | CTL.RDS.AUTOUPGRADE.001, CTL.RDS.MINOR.UPGRADE.001 (`auto_minor_version_upgrade == false`) | **Full** |

## Snapshot Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 9 | Public snapshots | CTL.RDS.SNAPSHOT.PUBLIC.001 (`snapshot.is_public == true`) | **Full** |
| 10 | Shared snapshots | CTL.RDS.SNAPSHOT.ENCRYPT.001 (unencrypted snapshots), CTL.RDS.SNAPSHOT.EXPORT.001 (unrestricted export) | **Full** |

## Operational Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 11 | Missing backups | CTL.RDS.BACKUP.001 (`backup.enabled == false`) | **Full** |
| 12 | Missing deletion protection | CTL.RDS.DELETEPROT.001, CTL.RDS.CLUSTER.DELETION.PROTECT.001 | **Full** |
| 13 | RDS Proxy not configured | None | **None** |

### Vector 13 detail: Not covered

No control checks for RDS Proxy configuration. RDS Proxy provides
connection pooling, IAM authentication at the proxy layer, and
TLS enforcement. Its absence is a defense-in-depth gap, not a
direct exposure — the underlying RDS SSL and IAM auth controls
cover the authentication surface.

**Gap classification: Gap B.** Requires observation property
`database.proxy.configured` on RDS instance assets. Lower priority
because RDS Proxy is a defense-in-depth measure, not a primary
security control.

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 14 | CloudTrail for RDS events | CTL.CLOUDTRAIL.ENABLED.001 (multi-region trail), CTL.RDS.EVENTS.001 (RDS event subscriptions), CTL.RDS.LOG.001 (audit logging) | **Full** |
| 15 | Enhanced monitoring | CTL.RDS.MONITORING.001 (`enhanced_monitoring_enabled == false`), CTL.RDS.PERFORMANCE.INSIGHTS.001 (Performance Insights + KMS) | **Full** |

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 2 | SG broad ingress on RDS (v2) | — | **CLOSED** | CTL.RDS.SG.BROAD.001 authored. |
| 13 | RDS Proxy (v13) | B | Low | Need `database.proxy.configured`. Defense-in-depth; SSL + IAM auth controls cover the primary auth surface. |

## Chain Coverage

Two chain definitions model RDS attack paths:

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `rds_public_exposure_path` | Public RDS + unencrypted + no deletion protection | RDS.PUBLIC.001, RDS.ENCRYPT.001, RDS.DELETEPROT.001 |
| `eol_database_phi_exposure` | End-of-life engine + unencrypted + public | RDS.ENGINE.EOL.001, RDS.ENCRYPT.001, RDS.PUBLIC.001 |

## Recommendations

**Ship immediately (0 implementation):** Tesla enables 22 RDS
controls + 2 chain definitions. This covers 13 of 15 vectors
fully, including public access, encryption, TLS, IAM auth,
snapshots, backups, deletion protection, monitoring, and logging.

**Close within one iteration (Gap B, medium effort):**
- Vector 2: RDS-specific security group check. Requires
  `database.security_group.has_broad_ingress` observation property.
  The property would be populated by the RDS extractor by
  resolving the instance's VPC security groups and checking
  their ingress rules.

**Defer (Low priority):**
- Vector 13: RDS Proxy detection. Defense-in-depth measure.
  Lower priority because CTL.RDS.SSL.001 and CTL.RDS.IAMAUTH.001
  cover the primary authentication surface.

## Observation Schema Assessment

The observation contract defines:

- **Asset types:** `aws_rds_instance`, `aws_rds_cluster`,
  `aws_rds_snapshot`
- **Property namespace:** `database.*` (kind, access, encryption,
  backup, logging, monitoring, engine_version, etc.)
- **Test fixtures:** 5 forge fixtures + 1 multi-control fixture
  demonstrating the property shapes

The RDS observation schema is mature. 22 controls exercise
properties across access, encryption, backup, monitoring,
snapshots, logging, and engine management. The only property
gap is security group ingress resolution (currently on EC2 SG
assets, not propagated to RDS instance assets) and proxy
configuration.

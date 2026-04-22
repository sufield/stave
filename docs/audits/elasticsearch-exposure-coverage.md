# Elasticsearch/OpenSearch Public Exposure Coverage

Incident: 8.7 billion records exposed via publicly accessible
Elasticsearch cluster without authentication (Chinese data leak,
2026). Preventable misconfiguration — publicly accessible data
store without authentication or encryption.

Audited: 2026-04-22

## Summary

**All 10 vectors fully covered.** Stave has 13 dedicated
CTL.OPENSEARCH.* controls covering every vector from the Chinese
leak incident: public accessibility, missing authentication,
missing encryption (at-rest and in-transit), permissive access
policies, non-VPC deployment, fine-grained access control, audit
logging, dashboard exposure, and snapshot encryption. The
observation schema defines `aws_opensearch_domain` assets with
`search_service.*` properties. No gaps for Elasticsearch/OpenSearch
detection.

The broader data store landscape reveals a category pattern: S3
(98 controls), RDS (23), and OpenSearch (13) have deep coverage.
DynamoDB (3) and ElastiCache (3) have minimal coverage. Six data
store services (Redshift, Neptune, DocumentDB, MemoryDB, Keyspaces,
QLDB) have zero controls.

## Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Public cluster | CTL.OPENSEARCH.PUBLIC.001 (`publicly_accessible == true`), severity: critical | **Full** |
| 2 | No authentication | CTL.OPENSEARCH.AUTH.001 (`auth_enabled == false`), CTL.OPENSEARCH.FGAC.001 (`fgac_enabled == false`), severity: critical/high | **Full** |
| 3 | No encryption in transit | CTL.OPENSEARCH.HTTPS.001 (`https_enforced == false`), CTL.OPENSEARCH.ENCRYPT.002 (`node_to_node_enabled == false`) | **Full** |
| 4 | No encryption at rest | CTL.OPENSEARCH.ENCRYPT.001 (`at_rest_enabled == false`), CTL.OPENSEARCH.SNAPSHOT.001 (snapshot encryption) | **Full** |
| 5 | Permissive access policy | CTL.OPENSEARCH.ACCESS.POLICY.001 (`policy_allows_wildcard == true`) | **Full** |
| 6 | Not in VPC | CTL.OPENSEARCH.VPC.001 (`vpc_enabled == false`), severity: critical | **Full** |
| 7 | Generic data store detection | Stave has the pattern applied to S3, RDS, and OpenSearch. Not generic — per-service controls. | **Full** (for OpenSearch) |
| 8 | CIS benchmark coverage | OpenSearch controls map to CIS checks for public access, encryption, VPC, auth. | **Full** |
| 9 | Public + no auth compound | CTL.OPENSEARCH.PUBLIC.001 + CTL.OPENSEARCH.AUTH.001 fire independently on same domain. No dedicated chain, but both controls fire with critical severity. | **Full** (individual) |
| 10 | Public + no encryption | CTL.OPENSEARCH.PUBLIC.001 + CTL.OPENSEARCH.ENCRYPT.001 fire independently. | **Full** (individual) |

## Additional OpenSearch Controls

Beyond the incident-specific vectors:

| Control | What it detects |
|---------|-----------------|
| CTL.OPENSEARCH.KIBANA.001 | OpenSearch Dashboards publicly accessible |
| CTL.OPENSEARCH.LOG.001 | Audit logging not enabled |
| CTL.OPENSEARCH.AUDIT.LOG.001 | Audit logs not configured |
| CTL.OPENSEARCH.INCOMPLETE.001 | Incomplete observation data |

## RDS Cross-Reference

| RDS control | OpenSearch equivalent | Status |
|-------------|---------------------|--------|
| CTL.RDS.PUBLIC.001 (public access) | CTL.OPENSEARCH.PUBLIC.001 | Exists |
| CTL.RDS.SSL.001 (TLS required) | CTL.OPENSEARCH.HTTPS.001 | Exists |
| CTL.RDS.ENCRYPT.001 (at-rest) | CTL.OPENSEARCH.ENCRYPT.001 | Exists |
| CTL.RDS.IAMAUTH.001 (IAM auth) | CTL.OPENSEARCH.AUTH.001, CTL.OPENSEARCH.FGAC.001 | Exists |
| CTL.RDS.LOG.001 (audit logging) | CTL.OPENSEARCH.LOG.001, CTL.OPENSEARCH.AUDIT.LOG.001 | Exists |
| CTL.RDS.BACKUP.001 (backups) | CTL.OPENSEARCH.SNAPSHOT.001 | Exists |
| CTL.RDS.MONITORING.001 (monitoring) | No equivalent | Gap |

The data-store security pattern (public access + auth + encryption
+ logging + backup) is consistently applied across S3, RDS, and
OpenSearch. The only OpenSearch gap relative to RDS is enhanced
monitoring.

## Data Store Coverage Landscape

| Service | Controls | Coverage | Gap |
|---------|----------|----------|-----|
| S3 | 98 | Deep | — |
| RDS | 23 | Deep | — |
| OpenSearch | 13 | Deep | — |
| DynamoDB | 3 | Minimal | Encryption, backup, autoscaling, VPC |
| ElastiCache | 3 | Minimal | At-rest encryption, backup, multi-AZ |
| Redshift | 0 | None | Entire service (Gap C) |
| Neptune | 0 | None | Entire service (Gap C) |
| DocumentDB | 0 | None | Entire service (Gap C) |
| MemoryDB | 0 | None | Entire service (Gap C) |
| Keyspaces | 0 | None | Entire service (Gap C) |
| QLDB | 0 | None | Entire service (Gap C) |
| Timestream | 0 | None | Entire service (Gap C) |

**The Chinese leak pattern (public data store + no auth) is
detectable for S3, RDS, and OpenSearch.** It is NOT detectable
for 6 other data store services because Stave has no controls
for them. Redshift is the highest-risk gap — it's a common data
warehouse with public access settings similar to RDS.

## Gaps and Classification

### OpenSearch-specific: No gaps

All 10 vectors fully covered by 13 existing controls. The Chinese
leak incident would be detected by:
- CTL.OPENSEARCH.PUBLIC.001 (critical) — public cluster
- CTL.OPENSEARCH.AUTH.001 (critical) — no authentication
- CTL.OPENSEARCH.VPC.001 (critical) — not in VPC
Three critical-severity findings on a single domain.

### Broader data store gap: Category gap

The category gap is the strategic finding. The "public data store
without authentication" pattern needs to be applied systematically:

| Priority | Service | Prowler checks | Risk |
|----------|---------|---------------|------|
| High | Redshift | 10 | Data warehouse — common, large datasets |
| Medium | DynamoDB (expand) | 9 | NoSQL — currently minimal coverage |
| Medium | ElastiCache (expand) | 8 | Cache — session data, credentials |
| Low | Neptune | 10 | Graph DB — specialized |
| Low | DocumentDB | ~5 | Document DB — MongoDB-compatible |
| Low | MemoryDB | ~2 | Redis-compatible — similar to ElastiCache |

## Recommendations

**No action needed for OpenSearch.** The Chinese leak pattern is
fully detectable today. The 13 controls cover every vector from
the incident.

**Broader data store coverage** is the strategic investment:
1. Redshift (Gap C — new asset type, ~10 controls, 1-2 iterations)
2. DynamoDB expansion (Gap B — 6 additional controls, 1 iteration)
3. ElastiCache expansion (Gap B — 5 additional controls, 1 iteration)
4. Neptune/DocumentDB (Gap C — new asset types, lower priority)

**Recommended: add a chain definition** for `public_data_store_exposure`
composing public-access + no-auth + no-encryption controls across
all data store services where these controls exist.

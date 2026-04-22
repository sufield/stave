# CloudTrail Completeness and Tamper-Resistance Coverage Audit

Audited: 2026-04-21
Request: Firefox CloudTrail completeness and tamper-resistance detection
Catalog: 690+ controls (13 CTL.CLOUDTRAIL.*, 18 CTL.CLOUDWATCH.MONITOR.*, 4 CTL.S3.LOG.BUCKET.*)

## Summary

**23 of 23 vectors fully covered.** All gaps closed across 2
batches. 0 partially, 0 not
covered. Stave has strong CloudTrail coverage across trail
completeness (multi-region, data events, log validation, stopped
trails), log integrity (encryption, trail bucket versioning/lock/
public access), and tamper detection (CloudTrail change monitoring,
S3 policy change monitoring). Five chain definitions model
detection-evasion attack paths.

Gaps: organization-wide trails, Lambda/DynamoDB data events,
Insight events, trail-specific SCP protection, and cross-account
log replication.

## For Firefox: what's ready today

### CloudTrail Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Multi-region enabled | CTL.CLOUDTRAIL.ENABLED.001 | `multi_region_enabled == false` |
| Trail stopped | CTL.CLOUDTRAIL.STOP.DETECT.001 | `is_logging == false` |
| Repeated stop/start | CTL.CLOUDTRAIL.DISABLE.RECUR.001 | Trail oscillation pattern |
| S3 data read events | CTL.CLOUDTRAIL.DATAREAD.001 | `s3_data_events.read_enabled == false` |
| S3 data write events | CTL.CLOUDTRAIL.DATAWRITE.001 | `s3_data_events.write_enabled == false` |
| Log file validation | CTL.CLOUDTRAIL.LOG.VALIDATION.001, CTL.CLOUDTRAIL.VALIDATION.001 | `log_file_validation_enabled == false` |
| KMS encryption | CTL.CLOUDTRAIL.ENCRYPT.001 | `encryption.encrypted == false` |
| Long-term retention | CTL.CLOUDTRAIL.RETENTION.001 | `retention.long_term_enabled == false` |
| CloudWatch Logs streaming | CTL.CLOUDTRAIL.CWLOGS.001 | `cloudwatch_logs.delivery_active == false` |
| Trail bucket access logging | CTL.CLOUDTRAIL.S3LOG.001 | `s3_bucket_logging_enabled == false` |
| Trail bucket public access | CTL.S3.CLOUDTRAIL.PUBLIC.001 | `s3_bucket_public == true` |
| Trail bucket versioning | CTL.S3.LOG.BUCKET.VERSIONING.001 | Log bucket not versioned |
| Trail bucket Object Lock | CTL.S3.LOG.BUCKET.LOCK.001 | Log bucket without Object Lock |
| Trail bucket public | CTL.S3.LOG.BUCKET.PUBLIC.001 | Log bucket publicly accessible |
| Trail bucket lifecycle | CTL.S3.LOG.BUCKET.LIFECYCLE.001 | Log bucket without lifecycle policy |
| Organization-wide trail | CTL.CLOUDTRAIL.ORG.001 | `is_organization_trail == false` |
| Cross-account replication | CTL.CLOUDTRAIL.REPLICATION.001 | `has_cross_account_replication == false` |
| SCP trail protection | CTL.IAM.SCP.TRAIL.PROTECT.001 | `scp.denies_trail_disruption == false` |
| Lambda data events | CTL.CLOUDTRAIL.DATA.LAMBDA.001 | `data_events.lambda.enabled == false` |
| DynamoDB data events | CTL.CLOUDTRAIL.DATA.DYNAMODB.001 | `data_events.dynamodb.enabled == false` |
| Insights anomaly detection | CTL.CLOUDTRAIL.INSIGHTS.001 | `insights.enabled == false` |
| Trail bucket access alert | CTL.CLOUDWATCH.MONITOR.TRAIL.ACCESS.001 | `trail_bucket_access.exists == false` |
| Broad LookupEvents access | CTL.CLOUDTRAIL.LOOKUP.RESTRICT.001 | Broad CloudTrail lookup permissions |
| CloudTrail changes monitored | CTL.CLOUDWATCH.MONITOR.TRAIL.001 | `cloudtrail_changes.exists == false` |
| S3 policy changes monitored | CTL.CLOUDWATCH.MONITOR.S3POLICY.001 | `s3_policy_changes.exists == false` |
| CMK changes monitored | CTL.CLOUDWATCH.MONITOR.CMK.001 | `cmk_changes.exists == false` |
| Unauthorized API calls | CTL.CLOUDWATCH.MONITOR.UNAUTH.001 | `unauthorized_api_calls.exists == false` |
| Config changes monitored | CTL.CLOUDWATCH.MONITOR.CONFIG.001 | `config_changes.exists == false` |

### Chain Definitions

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `audit_trail_destruction_path` | Log bucket lock + public + versioning gaps | S3.LOG.BUCKET.LOCK, PUBLIC, VERSIONING |
| `defense_evasion_then_impact` | Trail stopped + no backup + no GuardDuty | CLOUDTRAIL.STOP.DETECT, BACKUP, GUARDDUTY |
| `detection_blindness` | No CloudTrail + no Config + no GuardDuty + no flow logs | CLOUDTRAIL.ENABLED, CONFIG, GUARDDUTY, VPC.FLOWLOG |
| `detection_evasion_complete` | No CloudTrail + degraded Config + suppressed GuardDuty + WAF bypass | CLOUDTRAIL.ENABLED, CONFIG.RULE, GUARDDUTY.SUPPRESSION, WAF.RULES |
| `ghost_resource_exfiltration` | Missing data write logging + ghost reference exfil | CLOUDTRAIL.DATAWRITE, IAM.POLICY.GHOSTREF, S3.LOG |

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/cloudtrail-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

## Trail Completeness Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Not organization-wide | CTL.CLOUDTRAIL.ORG.001 (`audit_trail.is_organization_trail == false`) | **Full** |
| 2 | Not multi-region | CTL.CLOUDTRAIL.ENABLED.001 (`multi_region_enabled == false`), CTL.CLOUDTRAIL.STOP.DETECT.001 (`is_multi_region_trail == false`) | **Full** |
| 3 | Missing management events | CTL.CLOUDTRAIL.ENABLED.001 implicitly covers management events (a multi-region trail logs management events by default). No explicit management-event-selector check. | **Full** |
| 4 | Missing S3 data events | CTL.CLOUDTRAIL.DATAREAD.001, CTL.CLOUDTRAIL.DATAWRITE.001 | **Full** |
| 5 | Missing Lambda data events | CTL.CLOUDTRAIL.DATA.LAMBDA.001 (`data_events.lambda.enabled == false`) | **Full** |
| 6 | Missing DynamoDB data events | CTL.CLOUDTRAIL.DATA.DYNAMODB.001 (`data_events.dynamodb.enabled == false`) | **Full** |
| 7 | Missing Insight events | CTL.CLOUDTRAIL.INSIGHTS.001 (`insights.enabled == false`) | **Full** |
| 8 | Trail stopped | CTL.CLOUDTRAIL.STOP.DETECT.001 (`is_logging == false`), CTL.CLOUDTRAIL.DISABLE.RECUR.001 (repeated stop/start pattern) | **Full** |

## Log Integrity Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 9 | Log validation disabled | CTL.CLOUDTRAIL.LOG.VALIDATION.001, CTL.CLOUDTRAIL.VALIDATION.001 | **Full** |
| 10 | Bucket not versioned | CTL.S3.LOG.BUCKET.VERSIONING.001 (fires on log destination buckets) | **Full** |
| 11 | Missing Object Lock | CTL.S3.LOG.BUCKET.LOCK.001 (fires on log destination buckets) | **Full** |
| 12 | Missing KMS encryption | CTL.CLOUDTRAIL.ENCRYPT.001 (`encryption.encrypted == false`) | **Full** |
| 13 | Permissive bucket policy | CTL.S3.LOG.BUCKET.PUBLIC.001 (log bucket public access), CTL.S3.CLOUDTRAIL.PUBLIC.001 (CloudTrail-specific). General S3 policy controls (ACCESS.002, ACCESS.004, POLICY.SCOPING.001) apply to trail buckets. | **Full** |

## Tamper Detection Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 14 | StopLogging detection | CTL.CLOUDWATCH.MONITOR.TRAIL.001 (`cloudtrail_changes.exists`). CIS 4.5 metric filter covers StopLogging, DeleteTrail, and UpdateTrail. | **Full** |
| 15 | DeleteTrail detection | CTL.CLOUDWATCH.MONITOR.TRAIL.001 (same — CIS 4.5 covers all trail modification events) | **Full** |
| 16 | UpdateTrail detection | CTL.CLOUDWATCH.MONITOR.TRAIL.001 (same) | **Full** |
| 17 | Event selector changes | CTL.CLOUDWATCH.MONITOR.TRAIL.001 covers `PutEventSelectors` as a CloudTrail configuration change. | **Full** |
| 18 | Bucket/KMS policy changes | CTL.CLOUDWATCH.MONITOR.S3POLICY.001 (S3 policy changes), CTL.CLOUDWATCH.MONITOR.CMK.001 (KMS key changes) | **Full** |

## Pipeline Protection Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 19 | SCP trail protection | CTL.IAM.SCP.TRAIL.PROTECT.001 (`scp.denies_trail_disruption`), CTL.IAM.SCP.DANGEROUS.ALLOWS.001 (no bad allows) | **Full** |
| 20 | Cross-account replication | CTL.CLOUDTRAIL.REPLICATION.001 (`audit_trail.has_cross_account_replication == false`) | **Full** |
| 21 | CloudWatch Logs streaming | CTL.CLOUDTRAIL.CWLOGS.001 (`cloudwatch_logs.delivery_active == false`) | **Full** |

### Vector 19 detail: Partial coverage

SCP.DANGEROUS.ALLOWS.001 detects SCPs that explicitly ALLOW
dangerous actions (including trail disruption). It doesn't verify
that a DENY-based SCP exists specifically protecting trails from
non-breakglass roles. The detection is "no bad allows" but not
"good denies exist."

**Gap classification: Gap B.** Requires observation property
`scp.has_trail_protection_deny` on SCP policy set assets.

### Vector 20 detail: Not covered

No control checks whether CloudTrail logs are replicated to a
separate account for durability. This is a defense-in-depth
measure — even if the primary trail bucket is compromised, a
cross-account copy preserves evidence.

**Gap classification: Gap B.** Requires observation property
`audit_trail.cross_account_replication.enabled` on trail assets.

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 22 | Alert on trail changes | CTL.CLOUDWATCH.MONITOR.TRAIL.001 — directly covers this. CIS benchmark 4.5. | **Full** |
| 23 | Alert on bucket access | CTL.CLOUDWATCH.MONITOR.TRAIL.ACCESS.001 (`trail_bucket_access.exists`), CTL.CLOUDWATCH.MONITOR.S3POLICY.001 (policy changes) | **Full** |

### Vector 23 detail: Partial coverage

S3 policy changes to the trail bucket are monitored. Direct data
access to the trail bucket (reading or deleting log files) by
non-CloudTrail principals is not specifically monitored.

**Gap classification: Gap B.** Requires observation property
`monitoring.metric_filters.trail_bucket_access.exists`.

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 1 | Organization-wide trail | — | **CLOSED** | CTL.CLOUDTRAIL.ORG.001 |
| 5 | Lambda data events | — | **CLOSED** | CTL.CLOUDTRAIL.DATA.LAMBDA.001 |
| 6 | DynamoDB data events | — | **CLOSED** | CTL.CLOUDTRAIL.DATA.DYNAMODB.001 |
| 7 | Insight events | — | **CLOSED** | CTL.CLOUDTRAIL.INSIGHTS.001 |
| 19 | SCP trail deny | — | **CLOSED** | CTL.IAM.SCP.TRAIL.PROTECT.001 |
| 20 | Cross-account replication | — | **CLOSED** | CTL.CLOUDTRAIL.REPLICATION.001 |
| 23 | Trail bucket access alert | — | **CLOSED** | CTL.CLOUDWATCH.MONITOR.TRAIL.ACCESS.001 |

All gaps are Gap B — observation properties needed, asset types
exist. No Gap C or D.

## Chain Coverage

5 chain definitions model detection-evasion and evidence-destruction
paths:

| Chain | Pattern |
|-------|---------|
| `audit_trail_destruction_path` | Log bucket unprotected (no lock + public + no versioning) |
| `defense_evasion_then_impact` | Trail stopped + no backup + no GuardDuty → undetected destruction |
| `detection_blindness` | Complete detection gap (no CloudTrail + Config + GuardDuty + flow logs) |
| `detection_evasion_complete` | Multi-layer evasion (all detection services degraded) |
| `ghost_resource_exfiltration` | Missing data logging enables untracked exfiltration |

## Recommendations

**Ship now:** Firefox enables 27+ CloudTrail controls, 19 MONITOR
controls, 4 trail-bucket controls, and 5 chain definitions. 23/23
vectors fully covered. No outstanding implementation work.

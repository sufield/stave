# S3 Website and CloudFront Origin Coverage Audit

Audited: 2026-04-21
Request: Squarespace S3 website and CloudFront origin detection
Catalog: 690+ controls (98 CTL.S3.*, 10 CTL.CLOUDFRONT.*)

## Summary

**13 of 15 vectors fully covered.** 0 partially covered, 2 not
covered. The catalog has strong S3+CloudFront cross-domain coverage
including dedicated controls for CDN bypass detection
(CTL.S3.CDN.BYPASS.001), OAC/OAI migration (CTL.S3.CDN.OAC.001),
website hosting exposure (CTL.S3.WEBSITE.PUBLIC.001), and 10
CloudFront distribution controls. The observation contract defines
both `aws_cloudfront_distribution` and `aws_s3_bucket` asset types
with cross-domain properties (`storage.cdn_access.*`,
`storage.website.*`).

Gaps: CloudFront origin without OAC (missing the specific
has_oac_configured property), mixed public/private content
detection (outside observation model), and path-pattern exposure
(CloudFront behavior configuration not deeply parsed).

## For Squarespace: what's ready today

### S3 Website + CDN Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Website + public read | CTL.S3.WEBSITE.PUBLIC.001 | `website.enabled AND public_read` |
| CDN bypass (direct S3) | CTL.S3.CDN.BYPASS.001 | `public_read AND is_cloudfront_origin` |
| CDN exposure | CTL.S3.CDN.EXPOSURE.001 | Private bucket exposed via CloudFront |
| Legacy OAI (not OAC) | CTL.S3.CDN.OAC.001 | `cloudfront_oai.enabled == true` (should use OAC) |
| Dangling CDN origins | CTL.S3.DANGLING.ORIGIN.001 | S3 origin bucket doesn't exist |
| Public read (any) | CTL.S3.PUBLIC.001 | `public_read == true` |
| Wildcard principal | CTL.S3.ACCESS.002 | `has_wildcard_principal == true` |
| Effectively public policy | CTL.S3.ACCESS.004 | `policy_is_effectively_public == true` |
| External write | CTL.S3.ACCESS.003 | `has_external_write == true` |
| Missing scoping condition | CTL.S3.POLICY.SCOPING.001 | Broad policy without scoping condition |
| Block Public Access | CTL.S3.CONTROLS.001 | `public_access_fully_blocked == false` |
| Account-level PAB | CTL.S3.ACCOUNT.PAB.001 | Account PAB not enabled |
| All 4 PAB sub-flags | CTL.S3.PAB.*.001 (4 controls) | Individual PAB flags |
| Public write via policy | CTL.S3.POLICY.WRITE.001 | `write_via_resource == true` |

### CloudFront Distribution Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| HTTPS enforcement | CTL.CLOUDFRONT.HTTPS.ONLY.001 | `viewer_protocol.allows_http` |
| TLS minimum | CTL.CLOUDFRONT.TLS.001, CTL.CLOUDFRONT.TLS.MINIMUM.001 | TLS below 1.2 |
| Security headers | CTL.CLOUDFRONT.HEADERS.001 | Missing security response headers |
| WAF association | CTL.CLOUDFRONT.WAF.001 | Missing WAF web ACL |
| Access logging | CTL.CLOUDFRONT.LOGGING.001 | `logging.enabled == false` |
| Origin failover | CTL.CLOUDFRONT.ORIGIN.FAILOVER.001 | No failover configured |
| CORS misconfiguration | CTL.CLOUDFRONT.CORS.001 | Wildcard origin + credentials |
| No origin access control | CTL.CLOUDFRONT.ORIGIN.NOACCESS.001 | `cdn.origin.has_access_control == false` |
| Origin direct access | CTL.WAF.ORIGIN.LOCKDOWN.001 | Origin accepts direct internet traffic |

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/s3-cloudfront-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

## S3 Website Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Website hosting on private | CTL.S3.WEBSITE.PUBLIC.001 (`website.enabled AND public_read`). Detects website hosting combined with public read. | **Full** |
| 2 | Permissive website policy | CTL.S3.ACCESS.004 (`policy_is_effectively_public`), CTL.S3.ACCESS.002 (`has_wildcard_principal`), CTL.S3.POLICY.SCOPING.001 (missing scoping condition) | **Full** |
| 3 | Block Public Access disabled | CTL.S3.CONTROLS.001, CTL.S3.ACCOUNT.PAB.001, CTL.S3.PAB.*.001 (4 sub-flag controls) | **Full** |

## CloudFront Origin Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 4 | Missing OAC | CTL.CLOUDFRONT.ORIGIN.NOACCESS.001 (`cdn.origin.has_access_control == false`), CTL.S3.CDN.OAC.001 (legacy OAI detection) | **Full** |
| 5 | Misconfigured OAI | CTL.S3.CDN.OAC.001 (`cloudfront_oai.enabled == true` — flags OAI as needing migration to OAC) | **Full** |
| 6 | Direct S3 bypass | CTL.S3.CDN.BYPASS.001 (`public_read AND is_cloudfront_origin`). Directly addresses the bypass vector. | **Full** |
| 7 | S3 origin with public read | CTL.S3.CDN.BYPASS.001 (same control — detects public read on CloudFront origins), CTL.S3.PUBLIC.001 (general public read) | **Full** |

### Vector 4 detail: Partial coverage

CTL.S3.CDN.OAC.001 checks `cloudfront_oai.enabled == true` — it
flags buckets using legacy OAI and recommends OAC. It does NOT
detect origins with no access control at all (neither OAC nor OAI).
The "completely unprotected origin" case is partially covered by
CTL.S3.CDN.BYPASS.001 (which fires when the origin bucket is
public), but a non-public bucket without OAC/OAI that relies solely
on bucket policy would not be flagged.

**Gap classification: Gap B.** Requires observation property
`storage.cdn_access.has_origin_access_control` (bool). The existing
`cdn_access` namespace already has OAC/OAI properties.

## Policy/Access Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 8 | Non-CloudFront principals | CTL.S3.ACCESS.001 (`external_account_ids not_subset_of allowed_accounts`). The adopter configures `allowed_accounts` to include only the CloudFront account. | **Full** |
| 9 | Wildcard principal | CTL.S3.ACCESS.002 (`has_wildcard_principal`), CTL.S3.POLICY.SCOPING.001 (missing scoping condition) | **Full** |
| 10 | Missing policy conditions | CTL.S3.POLICY.SCOPING.001 (`policy_has_scoping_condition == false`). Directly checks for missing conditions. | **Full** |

## Content Segregation Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 11 | Mixed public/private content | No control. Content classification within a bucket requires data-level inspection, not configuration-level observation. | **None** |
| 12 | Path pattern exposure | No control checks CloudFront behavior path patterns against S3 prefix classification. | **None** |

### Vector 11 detail: Not covered

Mixed-content detection requires knowing what data is in each S3
prefix — this is a data classification problem, not a configuration
assessment. The observation model captures bucket-level properties,
not object-level content classification.

**Gap classification: Gap C.** Requires content classification
data (Macie output, data catalog tags) paired with CloudFront path
patterns. Outside the current observation model.

### Vector 12 detail: Not covered

CloudFront behavior path patterns (e.g., `/api/*`, `/admin/*`)
paired with S3 prefix sensitivity is not captured in the current
observation schema. The `cdn.*` properties cover distribution-level
settings but not per-behavior configuration.

**Gap classification: Gap C.** Requires CloudFront cache behavior
parsing + S3 prefix classification. Multi-asset correlation not
available in current engine.

## Compound Coverage Matrix

| # | Vector | Control(s) / Chains | Coverage |
|---|--------|---------------------|----------|
| 13 | Website + no OAC + public | CTL.S3.WEBSITE.PUBLIC.001 + CTL.S3.CDN.BYPASS.001 + CTL.S3.CONTROLS.001 fire independently on the same bucket. No dedicated chain. | **Full** (individual controls, no chain) |
| 14 | Auth bypass via direct S3 | CTL.S3.CDN.BYPASS.001 directly detects this pattern (`public_read AND is_cloudfront_origin`). CTL.WAF.ORIGIN.LOCKDOWN.001 detects origins accepting direct traffic. | **Full** |

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 15 | CloudTrail for S3/CF changes | CTL.CLOUDTRAIL.ENABLED.001 (multi-region trail), CTL.CLOUDWATCH.MONITOR.S3POLICY.001 (`s3_policy_changes.exists`), CTL.CLOUDWATCH.MONITOR.TRAIL.001 (CloudTrail config changes) | **Full** |

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 4 | Missing OAC (no access control at all) | — | **CLOSED** | CTL.CLOUDFRONT.ORIGIN.NOACCESS.001 |
| 11 | Mixed content | C | Low | Content classification outside observation model |
| 12 | Path pattern exposure | C | Low | Multi-asset behavior correlation not available |

## Chain Coverage

The `cdn_origin_exposure` chain composes three controls into a
compound detection for the full S3+CloudFront misconfiguration:

- CTL.S3.CDN.BYPASS.001 (direct S3 access on CloudFront origin)
- CTL.S3.CONTROLS.001 (Block Public Access disabled)
- CTL.S3.WEBSITE.PUBLIC.001 (website hosting with public read)

When all three fire on the same bucket, the chain produces a
compound-risk score surfacing the complete exposure pattern.

## Observation Schema Assessment

**CloudFront distribution assets:** `aws_cloudfront_distribution`
with `cdn.*` properties (viewer_protocol, tls, headers, logging,
waf, cors, origin_failover, origin_shield, geo_restriction).

**S3 CDN cross-domain properties:** `storage.cdn_access.*`
(is_cloudfront_origin, cloudfront_oai, cloudfront_oac,
bucket_policy_grants_cloudfront, distribution_id, distribution_domain).

**S3 website properties:** `storage.website.enabled`.

The schema is mature for the covered vectors. Gap B (vector 4)
requires one additional boolean property in the existing
`cdn_access` namespace.

## Recommendations

**Ship now:** Squarespace enables 26+ S3 and CloudFront controls
plus the `cdn_origin_exposure` chain. This covers 13 of 15 vectors
including the critical CDN bypass detection, website exposure,
OAI-to-OAC migration, public access blocking, and policy
analysis.

**Defer (Low priority, Gap C):**
- Vectors 11-12: Content segregation and path-pattern analysis.
  These require data-level classification (Macie integration)
  and multi-asset behavior correlation — significant observation
  model extensions.

The `cdn_origin_exposure` chain is now authored and available.

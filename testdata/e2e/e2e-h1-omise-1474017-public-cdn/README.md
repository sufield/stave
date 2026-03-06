# E2E Test: Omise CDN Public Bucket (HackerOne #1474017)

## Case Summary

- **Program**: Omise
- **HackerOne Report**: 1474017
- **Title**: Open S3 Bucket Accessible by any User
- **Bucket**: `omise-cdn-2`
- **CDN endpoint**: `https://cdn2.omise.co/`
- **Unsafe state**: Public READ + public LIST via both bucket policy and ACL. No Public Access Block enabled.

## Chosen Controls

| ID | Why |
|----|-----|
| `CTL.S3.PUBLIC.001` | Detects public read/list access — the primary finding in this case |
| `CTL.S3.CONTROLS.001` | Detects missing Public Access Block — the enabling condition for the exposure |

These are copied from `controls/s3/` (the canonical control directory).

Only these two controls are loaded to keep the test focused on the exact exposure pattern described in the report. Additional controls (ENCRYPT, LOG, VERSION, etc.) would also fire but are not part of this case's core finding.

## Snapshot Fields (Key Ones)

- `storage.visibility.public_read = true` — bucket objects readable by anyone
- `storage.visibility.public_list = true` — bucket listing exposed to anyone
- `storage.visibility.public_write = false` — no evidence of public write access
- `storage.visibility.public_read_via_policy = true` — policy grants `s3:GetObject` to `Principal: *`
- `storage.visibility.public_read_via_acl = true` — ACL grants READ to AllUsers
- `storage.visibility.public_list_via_policy = true` — policy grants `s3:ListBucket` to `Principal: *`
- `storage.controls.public_access_fully_blocked = false` — no PAB safety net
- `storage.controls.public_access_block.*` — all four PAB settings are `false`
- `vendor.aws.s3.cdn_endpoint = "https://cdn2.omise.co/"` — stored in vendor evidence

## What Is Not Representable

### CDN / Domain Mapping
The CDN endpoint (`https://cdn2.omise.co/`) is stored in `properties.vendor.aws.s3.cdn_endpoint` as vendor-specific evidence. There is no canonical field in the `storage.*` namespace for CDN/domain associations. No control currently evaluates this field.

### Takeover Risk
The HackerOne report mentions potential takeover risk (deleted objects, bucket reclaim). This requires modeling CloudFront/S3 origin associations, dangling bucket detection, and claimable namespace analysis — none of which exist in the current observation model or control set. No control IDs exist for takeover (`CTL.S3.TAKEOVER.*` or similar).

**Partial proxy**: `CTL.S3.CONTROLS.001` (Public Access Block) provides indirect coverage — a bucket with PAB enabled cannot be publicly exposed regardless of policy/ACL changes.

## How to Run

```bash
cd stave

# Build stave
go build -ldflags "-s -w" -o /tmp/stave ./cmd/stave

# Run this single case
/tmp/stave apply \
  --controls testdata/e2e/e2e-h1-omise-1474017-public-cdn/controls \
  --observations testdata/e2e/e2e-h1-omise-1474017-public-cdn/observations \
  --max-unsafe 168h \
  --now 2026-01-11T00:00:00Z

# Run via E2E harness (all cases)
BIN=/tmp/stave ./scripts/e2e.sh
```

Expected: exit code 3, 2 findings (CONTROLS.001 + PUBLIC.001), 1 resource, 1 unsafe.

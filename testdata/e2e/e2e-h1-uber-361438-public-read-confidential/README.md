# E2E Test: Uber Greece Public Bucket (HackerOne #361438)

## Case Summary

- **Program**: Uber
- **HackerOne Report**: 361438
- **Title**: Open AWS S3 Bucket at ubergreece.s3.amazonaws.com exposes confidential internal documents and files
- **Bucket**: `ubergreece`
- **Endpoint**: `ubergreece.s3.amazonaws.com`
- **Unsafe state**: Public READ via bucket policy (auth none). Not listable.
- **Data classification**: Confidential internal documents

## Chosen Controls

| ID | File | Why |
|----|------|-----|
| `CTL.S3.PUBLIC.001` | `controls/s3/CTL.S3.PUBLIC.001.yaml` | Broad: fires on any public read/list access |
| `CTL.S3.PUBLIC.002` | `controls/s3/CTL.S3.PUBLIC.002.yaml` | Narrow: fires on public access + sensitive classification (confidential) |

Both controls are copied from `controls/s3/` (canonical directory). PUBLIC.002 is the primary match for this case — it specifically detects publicly accessible buckets with sensitive data classification. PUBLIC.001 also fires as the broader check.

## Snapshot Fields (Key Ones)

- `storage.kind = "bucket"`
- `storage.visibility.public_read = true` — objects readable by anyone via policy
- `storage.visibility.public_list = false` — report does not claim listing was possible
- `storage.visibility.public_write = false` — no evidence of public write
- `storage.visibility.public_read_via_policy = true` — policy grants `s3:GetObject` to `Principal: *`
- `storage.visibility.public_read_via_acl = false` — no ACL-based public read
- `storage.tags.data-classification = "confidential"` — matches PUBLIC.002 predicate exactly
- `storage.controls.public_access_fully_blocked = false` — no PAB safety net
- `storage.encryption.at_rest_enabled = false` — no encryption configured

## What Is Not Represented

### Endpoint
The S3 endpoint `ubergreece.s3.amazonaws.com` is not stored in the observation JSON. There is no canonical field in `storage.*` for S3 endpoints. The bucket name `ubergreece` is sufficient to reconstruct the endpoint.

### Content Sensitivity
The `data-classification = "confidential"` tag is an organizational label. Stave is config-based and does not scan bucket contents. The real-world sensitivity (internal documents, files) is inferred from the tag, not from content inspection.

## How to Run

```bash
cd stave

# Build stave
go build -ldflags "-s -w" -o /tmp/stave ./cmd/stave

# Run this single case
/tmp/stave apply \
  --controls testdata/e2e/e2e-h1-uber-361438-public-read-confidential/controls \
  --observations testdata/e2e/e2e-h1-uber-361438-public-read-confidential/observations \
  --max-unsafe 168h \
  --now 2026-01-11T00:00:00Z

# Run via E2E harness (all cases)
BIN=/tmp/stave ./scripts/e2e.sh
```

Expected: exit code 3, 2 findings (PUBLIC.001 + PUBLIC.002), 1 resource, 1 unsafe.

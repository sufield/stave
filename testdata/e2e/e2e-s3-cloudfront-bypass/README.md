# E2E Test: CloudFront bypass — direct S3 access around CDN protections

## Case summary

- **Pattern**: S3 bucket is referenced as an origin by a CloudFront distribution AND is
  simultaneously readable on its direct S3 endpoint. Any CloudFront-layer controls (WAF,
  geographic restrictions, access logging, signed URLs) are bypassable by fetching the
  bucket URL directly.
- **Modeled assets**: 3 synthetic buckets — `bypass-exposed` (the bypass pattern),
  `cdn-fronted-private` (correctly fronted), `plain-public` (public but no CDN layer).
- **Regression guard**: `CTL.S3.CDN.BYPASS.001` fires only on the bypass bucket and
  stays silent on both the correctly-fronted bucket and the plain public bucket.

## Buckets

| ID | `access.public_read` | `cdn_access.is_cloudfront_origin` | Fires |
|----|:---:|:---:|:---:|
| `bypass-exposed` | true | true | ✅ BYPASS.001 |
| `cdn-fronted-private` | false | true | — |
| `plain-public` | true | false | — |

## Controls asserted

| Control | Severity | Fires on | Count |
|---------|:---:|---|:---:|
| `CTL.S3.CDN.BYPASS.001` | high | `public_read=true AND is_cloudfront_origin=true` | 1 |

## Expected result

- Exit code: 3
- Findings: 1
- Buckets evaluated: 3, unsafe: 1

## Notes

The fixture only ships `CTL.S3.CDN.BYPASS.001` in `controls/`, so the plain public bucket
does not fire `PUBLIC.001` here — that's asserted separately in the public-exposure
fixtures. This fixture is scoped to guarding the bypass predicate specifically.

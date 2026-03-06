# E2E Test: Shopify Multi-Bucket Public Exposure (HackerOne #94502)

## Case Summary

- **Program**: Shopify
- **HackerOne Report**: 94502
- **Pattern**: Multi-bucket public read/list; one bucket public write; remediation disables listing
- **Modeled assets**: 3 synthetic buckets
- **Timeline**: 2015-10-18 unsafe; 2015-10-26 listing disabled (read + write persist)

## Buckets

| ID | T1 State | T2 State |
|----|----------|----------|
| `shopify-owned-1` | read+list | read only (list disabled) |
| `shopify-owned-2` | read+list | read only (list disabled) |
| `shopify-writeable-1` | read+list+write | read+write (list disabled) |

## Controls Asserted

Full `controls/s3/` set (25 controls). Key controls that fire:

| Control | Buckets | Count |
|-----------|---------|-------|
| `CTL.S3.CONTROLS.001` | all 3 | 3 |
| `CTL.S3.ENCRYPT.004` | all 3 (`potentially_sensitive` != `public`) | 3 |
| `CTL.S3.PUBLIC.001` | all 3 (public_read still true) | 3 |
| `CTL.S3.PUBLIC.003` | shopify-writeable-1 (public_write=true) | 1 |
| `CTL.S3.PUBLIC.004` | all 3 (public_read_via_acl=true) | 3 |
| **Total** | | **13** |

## Engine Behavior Notes

- The engine caps `--now` to the latest observation timestamp (2015-10-26).
- T2 date is 2015-10-26 (8 days from T1) to exceed the strict >168h threshold.
- Listing was disabled at T2 (`public_list=false`), but `public_read` remains true so PUBLIC.001 still fires via its `any` predicate.
- Minimal observations — fields not present (encryption, versioning, logging, etc.) are treated as missing by the engine. ENCRYPT.004 fires because `data-classification=potentially_sensitive` is present and not excluded (`public` or `non-sensitive`), and KMS encryption fields are absent.

## Expected Result

- Exit code: 3
- Findings: 13
- Resources: 3 evaluated, 3 unsafe

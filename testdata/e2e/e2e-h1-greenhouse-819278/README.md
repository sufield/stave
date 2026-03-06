# E2E Test: Greenhouse.io Public Bucket (HackerOne #819278)

## Case Summary

- **Program**: Greenhouse.io
- **HackerOne Report**: 819278
- **Bucket**: `grnhse-marketing-site-assets`
- **Evidence URL**: `http://grnhse-marketing-site-assets.s3.amazonaws.com/`
- **Unsafe state**: `public_read=true`, `public_list=true`
- **Control asserted**: `CTL.S3.PUBLIC.001`

## Notes

The bucket was exposed via S3 website-style HTTP endpoint, allowing browse/list/download. In Stave this is represented as `public_read=true` + `public_list=true`. The endpoint URL is not modeled in the observation schema.

Minimal observation — only fields needed by PUBLIC.001 are populated. Two snapshots (T1 at 2026-01-01, T2 at 2026-01-11) are required for duration-based evaluation.

## Expected Result

- Exit code: 3
- Findings: 1 (PUBLIC.001)
- Resources: 1 evaluated, 1 unsafe

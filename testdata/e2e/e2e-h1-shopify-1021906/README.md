# E2E Test: Shopify Ping iOS Public Bucket (HackerOne #1021906)

## Case Summary

- **Program**: Shopify
- **HackerOne Report**: 1021906
- **Bucket**: `ping-api-production`
- **Endpoint** (narrative): `ping-api-production.s3.us-west-2.amazonaws.com`
- **Unsafe state**: `public_read=true`, `public_list=true`
- **Control asserted**: `CTL.S3.PUBLIC.001`

## Control

Only `CTL.S3.PUBLIC.001` is loaded. It fires on `public_read=true OR public_list=true`. Copied from `controls/s3/`.

## Observations

Two snapshots (T1 at 2026-01-01, T2 at 2026-01-11) are required for duration-based evaluation. Stave needs at least 2 snapshots to calculate unsafe duration exceeding the 168h threshold.

## Expected Result

- Exit code: 3 (violations found)
- Findings: 1 (PUBLIC.001)
- Resources: 1 evaluated, 1 unsafe

## How to Run

```bash
cd stave
BIN=/tmp/stave ./scripts/e2e.sh
```

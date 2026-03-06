# E2E Test: Mapbox Object-Level Public Read (HackerOne #202725)

## Case Summary

- **Program**: Mapbox
- **HackerOne Report**: 202725
- **Evidence**: Team-summary-only (no bucket name provided in report)
- **Modeled resource**: Bucket `mapbox-private-objects` (synthetic)
- **Timeline**: 2017-02-01 unsafe (`public_read=true`), 2017-02-09 still unsafe
- **Control asserted**: `CTL.S3.PUBLIC.001`

## Model Limitations

The original report describes **object-level** public-read ACLs, not bucket-level exposure. Stave MVP 1.0 does not represent per-object ACLs — only bucket-level effective exposure via `properties.storage.visibility.public_read`. This test models the case as "bucket has effective public read" (the closest representable state).

## Engine Behavior Notes

- Stave only reports **currently unsafe** resources. A T1-unsafe / T2-safe pattern produces 0 findings (the engine sees the resource as remediated). Both snapshots must show the unsafe state for the finding to fire.
- The engine caps `--now` to the latest observation timestamp. With observations in 2017, the effective `now` is 2017-02-09.
- The duration threshold is strictly greater than (`>`), not `>=`. A 168h duration (exactly 7 days) does not fire — T2 must be >7 days after T1.
- Exposure via object-level ACL is represented as `public_read_via_acl=true` at the bucket level.

## Expected Result

- Exit code: 3
- Findings: 1 (PUBLIC.001)
- Resources: 1 evaluated, 1 unsafe
- Duration: 192h (8 days, exceeds 168h threshold)

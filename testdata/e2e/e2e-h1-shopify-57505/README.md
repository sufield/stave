# E2E Test: Shopify Public List Without Intent (HackerOne #57505)

## Case Summary

- **Program**: Shopify
- **HackerOne Report**: 57505
- **Bucket**: `shopify-public-assets`
- **Unsafe state**: `public_read=true` (intended), `public_list=true` (NOT intended)
- **Control asserted**: `CTL.S3.PUBLIC.LIST.002`

## Scenario

Objects are public by design (`public_read_intended: "true"` tag present), but
anonymous bucket listing was unintended. The control fires because
`public_list=true` with no `public_list_intended` tag.

## Control

Only `CTL.S3.PUBLIC.LIST.002` is loaded. It fires when:
1. `properties.storage.kind == "bucket"`
2. `properties.storage.visibility.public_list == true`
3. `properties.storage.tags.public_list_intended` is missing OR not `"true"`

## Observations

- **T1** (2026-01-01): Unsafe — `public_list=true`, no `public_list_intended` tag
- **T2** (2026-01-11): Still unsafe — same state, not yet remediated

Both snapshots have `public_read=true` (intended) and `public_list=true` (unintended).
Two snapshots required for duration-based evaluation (240h > 168h threshold).

## Expected Result

- Exit code: 3 (violations found)
- Findings: 1 (LIST.002)
- Resources: 1 evaluated, 1 currently unsafe

## How to Run

```bash
cd stave
BIN=/tmp/stave ./scripts/e2e.sh
```

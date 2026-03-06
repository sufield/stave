# E2E Test: Shopify Arbitrary Write via Broad Signed Upload Policy (HackerOne #93691)

## Case Summary

- **Program**: Shopify
- **HackerOne Report**: 93691
- **Title**: Arbitrary write in private S3 bucket via broad signed upload policy scope
- **Pattern**: Private bucket + signed upload policy too broad (prefix wildcard instead of exact key)

## Modeling

The vulnerability is modeled as an asset of type `s3_upload_policy` with:
- `allowed_key_mode: "prefix"` — upload policy permits writes to any key under `files/`
- `allowed_prefix: "files/"` — the overly broad prefix scope

The bucket itself remains private (no public flags). The control evaluates the
policy resource, not the bucket.

## Control

Only `CTL.S3.WRITE.SCOPE.001` is loaded. It fires when all conditions are met:
1. `type == "s3_upload_policy"`
2. `s3_upload.operation == "write"`
3. `s3_upload.allowed_key_mode == "prefix"`

## Observations

- **T1** (2026-01-01): Unsafe — upload policy uses prefix mode (`files/`)
- **T2** (2026-01-11): Still unsafe — not yet remediated

Two snapshots required for duration-based evaluation (240h > 168h threshold).

## Expected Result

- Exit code: 3 (violations found)
- Findings: 1 (WRITE.SCOPE.001)
- Resources: 2 evaluated (bucket + policy), 1 currently unsafe (policy)

## How to Run

```bash
cd stave
BIN=/tmp/stave ./scripts/e2e.sh
```

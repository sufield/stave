# e2e-h1-shopify-94087: Tenant Isolation via Path Traversal in Presigned URLs

## HackerOne Report

- **Program**: Shopify
- **Report**: #94087
- **Pattern**: Tenant isolation breach via `../` path traversal in signed S3 object keys

## Scenario

A shared S3 bucket uses prefix-based tenant isolation (`shops/{shop_id}/`).
An app-signer identity generates presigned download URLs but does NOT enforce
the tenant prefix, allowing `../` traversal to escape the per-tenant scope.

The bucket itself is **private** (all public access blocked). The vulnerability
is in the signer's configuration, not in bucket ACLs or policies.

## Observations

| Timestamp | State |
|-----------|-------|
| 2015-10-15T00:00:00Z | Unsafe: signer allows traversal (`enforce_prefix=false;allow_traversal=true`) |
| 2015-10-23T00:00:00Z | Still unsafe: signer config unchanged |

## Expected Result

- **Exit code**: 3 (violations)
- **Findings**: 2
  - `CTL.S3.TENANT.ISOLATION.001` — signer allows tenant prefix bypass
  - `CTL.S3.ENCRYPT.004` — sensitive data without KMS encryption
- **Unsafe duration**: 192 hours (> 168h threshold)

## Key Control

`CTL.S3.TENANT.ISOLATION.001` uses the `any_match` operator to iterate over
snapshot identities and the `contains` operator for substring matching on the
identity's purpose field.

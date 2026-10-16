# E2E Test: Dangling A Record to Released Elastic IP (HackerOne Shopify #1295497)

## Case Summary

- **Program**: Shopify
- **HackerOne Report**: 1295497
- **Asset**: DNS record `api-staging.shopify.com`
- **Unsafe state**: `has_dangling_eip = true` (EIP released, A record still live)
- **Control asserted**: `CTL.ROUTE53.DANGLING.EIP.001`

## Scenario

EC2 instance terminated, Elastic IP released back to pool, but DNS A record
still points at the old address. Any AWS account can re-allocate the IP and
receive traffic for `api-staging.shopify.com`.

## Observations

- **T1** (2026-01-01): `has_dangling_eip = true`, `ip_allocated = false`
- **T2** (2026-01-11): Same state, not yet remediated

## Expected Result

- Exit code: 3 (findings found)
- Findings: 1
- Resources: 1 evaluated, 1 currently unsafe

# E2E Test: CloudTrail ElastiCache Endpoint Blind Spot (HackerOne #3021451)

## Case Summary

- **Program**: AWS
- **HackerOne Report**: 3021451
- **Asset**: CloudTrail trail (org-trail)
- **Unsafe state**: `elasticache_endpoint_coverage.all_endpoints_logged = false`
- **Control asserted**: `CTL.CLOUDTRAIL.ELASTICACHE.ENDPOINT.BLIND.001`

## Scenario

CloudTrail trail is multi-region, logging enabled, all events captured — but
ElastiCache exposes a non-production endpoint (`elasticache.us-east-1.api.aws`)
whose calls bypass CloudTrail entirely. The control fires because the trail
does not cover all reachable ElastiCache endpoints.

## Observations

- **T1** (2026-01-01): Trail enabled, `all_endpoints_logged = false`
- **T2** (2026-01-11): Same state, not yet remediated

## Expected Result

- Exit code: 3 (findings found)
- Findings: 1
- Resources: 1 evaluated, 1 currently unsafe

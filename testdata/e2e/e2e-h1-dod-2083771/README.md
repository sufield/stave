# E2E Test: EC2 IMDS Hop Limit Excessive (HackerOne DoD #2083771)

## Case Summary

- **Program**: DoD
- **HackerOne Report**: 2083771
- **Asset**: EC2 instance `i-0a1b2c3d4e5f`
- **Unsafe state**: `imds_hop_limit_excessive = true` (hop limit 2)
- **Control asserted**: `CTL.EC2.IMDS.HOPLIMIT.001`

## Scenario

Jenkins on EC2 with IMDSv1 permitted and hop limit 2. The metadata endpoint
answers unauthenticated GET requests and the hop limit allows containers one
hop away to reach it — an SSRF in Jenkins yields IAM role credentials.

## Observations

- **T1** (2026-01-01): `imds_hop_limit_excessive = true`, hop limit 2
- **T2** (2026-01-11): Same state, not yet remediated

## Expected Result

- Exit code: 3 (findings found)
- Findings: 1
- Resources: 1 evaluated, 1 currently unsafe

# E2E Test: EKS aws-auth Broad system:masters Mapping (Kubernetes #1238482)

## Case Summary

- **Program**: Kubernetes / aws-load-balancer-controller
- **Report**: 1238482
- **Asset**: EKS aws-auth mapping for `TenantB-IngressController`
- **Unsafe state**: `groups_include_masters = true`, `is_break_glass_admin = false`
- **Control asserted**: `CTL.EKS.AWSAUTH.MASTERS.BROAD.001`

## Scenario

Shared EKS cluster maps a tenant's ingress controller IAM role to
`system:masters`. The role is not a break-glass admin — it's a workload role
that should have namespace-scoped RBAC, not cluster-admin.

## Observations

- **T1** (2026-01-01): `groups_include_masters = true`, not break-glass
- **T2** (2026-01-11): Same state, not yet remediated

## Expected Result

- Exit code: 3 (findings found)
- Findings: 1
- Resources: 1 evaluated, 1 currently unsafe

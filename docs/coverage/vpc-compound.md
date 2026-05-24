# VPC compound coverage map

Maps the AWS compound control authoring plan's Phase 2 (VPC) 6
sub-families against existing Stave controls and chains.

## Headline finding

VPC has **77 atomic controls and 0 compound-scope controls today**
per the classifier. Like S3, VPC observations are per-resource
(`network.kind`, `network.security_group`, `network.subnet`, etc.)
— no cross-asset prefix lives in the predicate AST. The
classifier prefix extension that worked for IAM doesn't apply.

**The substantial VPC compound surface lives in chains: 31
chains touch at least one VPC control today** (with this commit,
32). Representative shapes already shipping:

- `chains/data_exfiltration_path.yaml`
- `chains/detection_blindness.yaml`
- `chains/ec2_direct_exposure.yaml`
- `chains/ecs_ssrf_credential_theft.yaml`
- `chains/lateral_movement_path.yaml`
- `chains/open_sg_lateral_movement_path.yaml`
- `chains/peering_lateral_movement.yaml`
- `chains/vpc_clientvpn_exposure.yaml`
- `chains/vpc_database_exposure.yaml`
- `chains/vpc_default_exposure.yaml`
- `chains/vpc_dns_exfiltration.yaml`
- `chains/vpc_dual_stack_exposure.yaml`
- `chains/vpc_endpoint_bypass.yaml`
- `chains/vpc_endpoint_evasion.yaml`
- `chains/network_ghost_exposure.yaml`
- (+ 16 more cross-service chains involving VPC legs)

## Plan sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Public-surface composition (compute + permissive SG + sensitive workload) | covered | `ec2_direct_exposure`, `vpc_database_exposure`, `data_exfiltration_path` |
| 2 | Multi-layer network control intersection (SG vs NACL) | partial | `open_sg_lateral_movement_path` covers SG side; explicit SG-vs-NACL chain is a gap |
| 3 | VPC endpoint policy gaps | covered | `vpc_endpoint_bypass`, `vpc_endpoint_evasion` |
| 4 | Peering / Transit Gateway reachability | covered | `peering_lateral_movement` |
| 5 | Internet gateway routing surprises | covered (this commit) | **NEW** `vpc_igw_routing_surprise` (IGW unnecessary + main RT public + subnet auto-public conjunction) |
| 6 | DNS resolution composition (Route 53 private zones) | covered | `vpc_dns_exfiltration` |

**Summary:** 5 covered, 1 partial, 0 gap.

## What this commit ships for VPC

- **1 net-new chain:** `chains/vpc_igw_routing_surprise.yaml`
  (sub-family 5 — IGW UNNECESSARY + ROUTETABLE.MAIN.PUBLIC +
  SUBNET.AUTOPUBLIC). Threshold 2; severity high; preconditions
  network_access_vpc; postconditions initial_access.

## Why ~30 net-new wasn't the right target

The plan sized Phase 2 at ~30 net-new compound controls. The
audit reveals VPC already has 31 chains substantiating compound
risk across 5 of 6 sub-families. The remaining sub-family
(multi-layer SG-vs-NACL) is one chain away from covered — adding
it is a future Phase-2-followup commit. Authoring 30 fresh
controls would massively duplicate existing chain coverage.

## Notes for follow-up

- **Sub-family 2 (SG vs NACL):** worth one explicit chain when an
  SG-allows + NACL-denies-conflict control or vice versa exists.
  Currently the multi-layer effective-permission composition
  isn't expressible as a single atomic control without
  observation-extractor cross-asset analysis.
- **Compound-share trajectory:** unchanged at 6.77%
  (chains aren't classifier-counted). VPC chain count
  31 → 32 with this commit.

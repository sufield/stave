# OpenSearch compound coverage map

Ninth coverage map in the series (after IAM / S3 / VPC / KMS /
Lambda / ECS-EKS / RDS / Step Functions). OpenSearch ships
**27 chains** — the second-largest unmapped service in the
catalog after Step Functions (30), which is why it's the next
coverage-map iteration.

The AWS compound control authoring plan
(`bizacademy/aws-compound-control-authoring-plan.md`) did NOT
enumerate OpenSearch sub-families originally. Like RDS and Step
Functions, this is post-hoc mapping because the chain inventory
already covers most of the compound surface and the comparison
story benefits from parity.

## Headline finding

OpenSearch has **27 chains** spread across 9 functional
sub-families. The chain catalog represents the search-cluster
compound attack surface: domain access control composes with
network exposure, IAM trust, encryption custody, backup
posture, plugin lifecycle, and (for newer service variants)
the AOSS / OSIS surfaces.

**OpenSearch-touching chains shipping today: 27.** The
representative shapes:

- `chains/opensearch_authn_unsafe.yaml` —
  master-user / IAM / SAML composition where the authentication
  layer fails-open or misroutes
- `chains/opensearch_policy_action_overshare.yaml` —
  domain-access policy grants overly broad action set
  (es:* on Resource:*, indices/* with no role-mapping
  constraint)
- `chains/opensearch_crossaccount_unsafe.yaml` —
  cross-account domain access without aws:SourceAccount /
  aws:SourceArn / sts:ExternalId
- `chains/opensearch_endpoint_exposure.yaml` —
  domain endpoint reachable from the public internet AND
  domain-access policy permits action sets the network
  layer doesn't gate
- `chains/opensearch_tls_decay.yaml` —
  TLS version + cipher suite + HTTPS-enforcement
  composition (the in-transit hygiene chain)
- `chains/opensearch_backup_unsafe.yaml` —
  manual + automated snapshot policy + retention + S3 backup-
  bucket cross-account-trust composition
- `chains/opensearch_aoss_unsafe.yaml` —
  OpenSearch Serverless data-access-policy + network-access-
  policy + encryption-policy composition (AOSS-specific
  pattern)
- `chains/opensearch_osis_unsafe.yaml` —
  Ingestion pipeline + source-credential + sink-permission
  composition (OSIS-specific pattern)

## Sub-family coverage

| # | Sub-family | Status | Chains |
|---|---|---|---|
| 1 | Authentication & authorization (master user, IAM, SAML, role mapping, action policies) | covered | `opensearch_authn_unsafe`, `opensearch_authn_role_mapping_decay`, `opensearch_saml_unhealthy`, `opensearch_policy_action_overshare`, `opensearch_policy_audit_drift`, `opensearch_policy_governance_decay` |
| 2 | Cross-account / cross-cluster boundaries | covered | `opensearch_crossaccount_unsafe`, `opensearch_crosscluster_unsafe` |
| 3 | Network exposure & TLS (endpoint reachability, TLS version, HTTPS enforcement) | covered | `opensearch_endpoint_exposure`, `opensearch_tls_decay` |
| 4 | Audit & logging (audit log completeness, log pipeline health, slow logs) | covered | `opensearch_audit_completeness_decay`, `opensearch_log_pipeline_unhealthy`, `opensearch_slowlog_blind` |
| 5 | Backup & resilience (snapshot policy, retention, recovery posture) | covered | `opensearch_backup_unsafe`, `opensearch_backup_hygiene_decay`, `opensearch_resilience_unsafe` |
| 6 | Cluster operations & health (capacity, cluster-health monitoring, operational visibility) | covered | `opensearch_cluster_health_blind`, `opensearch_capacity_blind`, `opensearch_capacity_decay`, `opensearch_operational_blind` |
| 7 | Engine / plugin / ISM lifecycle (engine version, plugin governance, index state management) | covered | `opensearch_engine_decay`, `opensearch_plugin_unsafe`, `opensearch_ism_decay` |
| 8 | AOSS / OSIS (newer service surfaces) | covered | `opensearch_aoss_unsafe`, `opensearch_osis_unsafe` |
| 9 | Governance & lifecycle (cost drift, governance posture) | covered | `opensearch_governance_unsafe`, `opensearch_cost_drift` |
| 10 | Ghost-reference (domain → deleted master role / KMS key / VPC / log group / S3 backup bucket) | **gap** | none — no `opensearch_ghost_*` chain exists; same structural pattern as the Step Functions ghost-reference gap documented in `stepfunctions-compound.md` |

**Summary:** 9 sub-families covered, 1 gap (ghost-reference).

Same shape as the Step Functions coverage map: substantial
chain coverage across operational sub-families, one structural
gap for the ghost-reference pattern that ships for most other
services in the catalog.

## What this comparison-story commit gains

`turbot/steampipe-mod-aws-compliance` covers OpenSearch with
per-attribute framework controls — encryption-at-rest enabled,
HTTPS enforcement, fine-grained access control toggled,
cognito-authn configured, node-to-node encryption — across CIS,
AWS Foundational Security Best Practices, and HIPAA mappings.
That coverage is correct for the per-resource compliance axis.

What framework-mod controls structurally can't see is the
compound shape: "endpoint reachable from public internet AND
domain-access policy permits es:* on Resource:* AND
fine-grained access control disabled" reads as 3 separate
framework controls each correctly firing on its own attribute,
with no benchmark control naming the *conjunction* as the
higher-risk pattern (the OpenSearch cluster is effectively
internet-readable with no per-action enforcement). Stave's
`opensearch_endpoint_exposure` + `opensearch_policy_action_overshare`
chains name exactly that conjunction.

The two surfaces compose: framework mod for per-resource
compliance against named frameworks, Stave's OpenSearch chains
for the cluster-compositional patterns operators recognize from
incident analyses (publicly-exposed search clusters processing
PHI; cross-account search domains without trust scoping).
Both render in Powerpipe; both should run.

## Open gap — ghost-reference for OpenSearch

Per the sub-family table, the one documented gap is
ghost-reference for OpenSearch. The pattern would be:

- domain references a master role ARN that's been deleted
- domain references a KMS key ID/ARN that no longer exists
  (the key's been scheduled for deletion or already deleted)
- domain is VPC-attached to a VPC / subnet / security group
  that's been removed
- domain logs to a CloudWatch log group that was deleted
- domain's snapshot policy references an S3 bucket that's
  been deleted or moved to another account

Same shape as the Step Functions ghost-reference gap
(`stepfunctions-compound.md`). Adding the chain is a small
follow-up iteration in the "author 1 chain per service for
the clearest gap" pattern the session established.

Not authored in this commit — coverage maps are documentation
artifacts; chain authoring is its own commit shape per the
session's discipline.

## What this commit ships

- **1 coverage document:** this file. Establishes the
  OpenSearch compound surface as 27 chains across 9 covered
  sub-families + 1 gap.
- **0 net-new chains.** The 27 existing chains cover 9 of
  the 10 sub-families identified in this audit; the 10th
  (ghost-reference) is the documented gap for a follow-up
  iteration.

## Audit notes

OpenSearch's compound surface is unusually rich for a
data-plane service: 27 chains across 9 sub-families. The
reason is partly that OpenSearch combines three deployment
shapes (Managed Service / Serverless / Ingestion Pipeline)
each with its own access-policy + network-policy + encryption-
policy decomposition. The `aoss_unsafe` + `osis_unsafe` chains
specifically cover the AOSS / OSIS surfaces — newer service
variants that the per-attribute framework benchmarks haven't
caught up to as completely as the original Managed Service
surface has.

This is a case where Stave's chain catalog leads framework-
benchmark coverage on the newer service variants, not because
Stave is comprehensive in some absolute sense but because the
compound-shape approach scales by chain-authoring (YAML edits)
rather than per-service framework-mapping (which lags by
provider release cycle).

No observation-contract gaps surfaced for OpenSearch
specifically. The chain inventory composes existing atomic
controls without requiring new asset types or extractor
extensions. If the ghost-reference chain lands, it likely
needs cross-asset reference-existence booleans the extractor
would populate — same shape as the S3 / RDS ghost-reference
patterns already shipped.

## Coverage maps shipped this session

  1. IAM             (Phase 1 — session start)
  2. VPC             (Phase 2)
  3. KMS             (Phase 3)
  4. S3              (Phase 4)
  5. Lambda          (Phase 5)
  6. ECS-EKS         (Phase 6)
  7. RDS             (bonus, mid-session)
  8. Step Functions  (later session)
  9. OpenSearch      (this commit)

**9 of 97 unique chain-prefix services** now have coverage
maps. Next-candidate services by chain count: eventbridge (27),
ec2 (18), cloudfront (16), apigw (16). Each is a similar
small-effort coverage map; the comparison story gains one more
service per iteration.

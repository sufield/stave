# Step Functions compound coverage map

Eighth coverage map in the series (after IAM / S3 / VPC / KMS /
Lambda / ECS-EKS / RDS). Step Functions ships **30 chains** —
the largest unmapped service in the catalog at session entry,
which is why it's the next coverage-map iteration after the RDS
bonus map.

The AWS compound control authoring plan
(`bizacademy/aws-compound-control-authoring-plan.md`) did NOT
enumerate Step Functions sub-families originally — like RDS,
this is post-hoc mapping because the chain inventory already
covers most of the compound surface and the comparison story
benefits from parity.

## Headline finding

Step Functions has **30 chains** spread across 8 functional
sub-families. The chain catalog represents the substantial
cross-resource attack surface that single-control framework
scanners can't see: state-machine execution flows compose with
IAM roles, KMS keys, Lambda integrations, logging
infrastructure, and cross-account boundaries in ways no per-
resource control can catch.

**Step-Functions-touching chains shipping today: 30.** The
representative shapes:

- `chains/stepfunctions_role_perms_unscoped.yaml` —
  multi-defect unscoped permissions (lambda:InvokeFunction on
  `*`, dynamodb:* on `*`, sts:AssumeRole on `*`, etc.)
- `chains/stepfunctions_role_trust_unsafe.yaml` —
  confused-deputy + cross-service trust + missing source-account
  conditions
- `chains/stepfunctions_iam_policy_unsafe.yaml` —
  StartExecution to wildcard principal, states:* on `*`,
  control-plane actions on non-admin role
- `chains/stepfunctions_crossaccount_unsafe.yaml` —
  cross-account grant without aws:SourceAccount, without
  sts:ExternalId, or without principal restriction
- `chains/stepfunctions_encryption_unsafe.yaml` —
  AWS-owned key + per-execution encryption off + customer-
  managed key custody loss
- `chains/stepfunctions_log_unhealthy.yaml` — Log Level OFF/
  ERROR + retention < 365 days + missing log group + Express
  logs unconfigured
- `chains/stepfunctions_alarms_blind.yaml` — missing alarms
  on ExecutionsFailed, ExecutionThrottled, ExecutionTime SLO,
  Activity/Lambda schedule time
- `chains/stepfunctions_asl_error_handling_missing.yaml` —
  Task/Parallel/Map states without Catch; Choice state without
  Default
- `chains/stepfunctions_lambda_timeout_unsafe.yaml` —
  Lambda Timeout > Task TimeoutSeconds + callback function
  doesn't honor heartbeat + retry handling missing

## Sub-family coverage

| # | Sub-family | Status | Chains |
|---|---|---|---|
| 1 | IAM identity & trust (role perms, trust policy, cross-account, role decay, IAM policy) | covered | `stepfunctions_role_perms_unscoped`, `stepfunctions_role_trust_unsafe`, `stepfunctions_iam_policy_unsafe`, `stepfunctions_crossaccount_unsafe`, `stepfunctions_role_decay` |
| 2 | ASL definition correctness (concurrency, error handling, failure visibility, retry, state design) | covered | `stepfunctions_asl_concurrency_unsafe`, `stepfunctions_asl_error_handling_missing`, `stepfunctions_asl_failure_invisible`, `stepfunctions_asl_retry_unsafe`, `stepfunctions_asl_state_design_unsafe` |
| 3 | Encryption & data protection (at-rest, in-transit, KMS custody) | covered | `stepfunctions_encryption_unsafe`, `stepfunctions_dm_data_unsafe`, `stepfunctions_kms_hygiene_decay` |
| 4 | Logging & observability (log level, retention, alarms, drift) | covered | `stepfunctions_log_unhealthy`, `stepfunctions_alarms_blind`, `stepfunctions_observability_decay` |
| 5 | Lambda integration (timeout, versioning, governance) | covered | `stepfunctions_lambda_timeout_unsafe`, `stepfunctions_lambda_versioning_unsafe`, `stepfunctions_lambda_governance_decay` |
| 6 | Integration edges (sync, async, token, cross-service) | covered | `stepfunctions_sync_unsafe`, `stepfunctions_async_decay`, `stepfunctions_token_unsafe`, `stepfunctions_integration_edges_unsafe` |
| 7 | Operations & lifecycle (governance, compliance, cost, IaC drift, versioning, operational) | covered | `stepfunctions_governance_decay`, `stepfunctions_compliance_unsafe`, `stepfunctions_cost_governance_decay`, `stepfunctions_iac_drift`, `stepfunctions_versioning_unsafe`, `stepfunctions_operational_decay` |
| 8 | Resilience (failover, recovery, throttle) | covered | `stepfunctions_resilience_decay` |
| 9 | Ghost-reference (state machine → deleted Lambda/Activity/IAM role/log group) | **gap** | none — no `stepfunctions_ghost_*` chain exists; ghost-reference for Step Functions would catch the recurring "state machine references deleted target" misconfiguration |

**Summary:** 8 sub-families covered, 1 gap (ghost-reference).

Compared to RDS (10 sub-families: 9 covered, 1 partial, 0 gap)
and S3 (6 sub-families: 6 covered, 1 partial, 0 gap), Step
Functions has the broadest coverage by chain count (30 vs RDS's
19) but one structural gap that maps cleanly to the
ghost-reference pattern shipped for other services
(S3 / CloudFront / Cognito / EKS / ECS / EventBridge / Secrets
Manager / SNS / SQS, etc.).

## What this comparison-story commit gains

`turbot/steampipe-mod-aws-compliance` covers Step Functions
with per-attribute framework controls — encryption state,
logging configuration, IAM policy compliance — across CIS, AWS
Foundational Security Best Practices, and SOC 2 mappings.
That coverage is correct for the per-resource compliance axis.

What framework-mod controls structurally can't see is the
compound shape: "ASL definition has Task without Catch AND
Lambda integration timeout misaligned AND missing
ExecutionsFailed alarm" reads as 3 separate framework controls
each correctly firing on its own attribute, with no benchmark
control naming the *conjunction* as the higher-risk pattern
(the workflow runs, fails silently, no operator notification,
no recovery path). Stave's `stepfunctions_asl_failure_invisible`
+ `stepfunctions_alarms_blind` chains name exactly that
conjunction.

The two surfaces compose: framework mod for per-resource
compliance against named frameworks, Stave's Step Functions
chains for the workflow-compositional patterns operators
recognize from incident analyses (silent-failure workflows
processing payment data; cross-account state machines without
trust scoping). Both render in Powerpipe; both should run.

## Open gap — ghost-reference for Step Functions

Per the sub-family table, the one documented gap is
ghost-reference for Step Functions. The pattern would be:

- state machine ASL definition references a Lambda function
  ARN that no longer exists in the account
- state machine references an Activity ARN that's been
  deregistered
- state machine's execution role ARN was deleted but the
  state machine wasn't deleted
- state machine logs to a CloudWatch log group that was
  deleted

Adding this chain is a small follow-up iteration in the
"author 1 chain per service for the clearest gap" pattern the
session established with `chains/s3_bucket_endpoint_unrestricted`
(S3 sub-family 3) and `chains/s3_object_lambda_privesc` (S3
sub-family 4). The pattern: identify the gap → author 1
chain composing existing atomic controls → update this
coverage map → ship.

Not authored in this commit — coverage maps are documentation
artifacts; chain authoring is its own commit shape per the
session's discipline. The gap is documented; the chain
authoring is a focused follow-up iteration.

## What this commit ships

- **1 coverage document:** this file. Establishes the Step
  Functions compound surface as 30 chains across 8 covered
  sub-families + 1 gap.
- **0 net-new chains.** The 30 existing chains cover 8 of the
  9 sub-families identified in this audit; the 9th
  (ghost-reference) is the documented gap for a follow-up
  iteration.

## Audit notes

Step Functions is unusually compound-rich for its catalog
position: 30 chains is more than RDS (19), S3 (16),
Lambda / KMS / VPC / ECS-EKS (each smaller). The reason is
Step Functions' ASL is itself a composition language — every
state machine IS a multi-step workflow that composes IAM roles,
Lambda integrations, error handling, logging, and timing.
Naturally compound by domain.

The 30 chains correspond roughly to the cross-product of:
- 5 ASL state types × 6 attribute classes (the inner
  per-state correctness chains)
- 4 integration surfaces × 3 IAM/encryption/logging axes
  (the cross-resource composition chains)
- 1 ghost-reference variant (the open gap above)

The pattern density matches the domain. Most other services
the comparison-story corpus calls out have narrower chain
counts because the per-resource correctness surface is smaller.

No observation-contract gaps surfaced for Step Functions
specifically. The chain inventory composes existing atomic
controls without requiring new asset types or extractor
extensions. If the ghost-reference chain lands, it likely
needs `properties.workflow.references.target_exists` or
similar pre-computed booleans the extractor would populate
from cross-asset analysis — same shape as the RDS
`rds_ghost_cascade` chain or the S3 `CTL.S3.BUCKET.TAKEOVER.001`
extractor pattern.

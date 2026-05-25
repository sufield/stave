# EventBridge compound coverage map

Tenth coverage map in the series (after IAM / S3 / VPC / KMS /
Lambda / ECS-EKS / RDS / Step Functions / OpenSearch).
EventBridge ships **27 chains** — tied with OpenSearch for the
second-largest unmapped service after Step Functions.

The AWS compound control authoring plan
(`bizacademy/aws-compound-control-authoring-plan.md`) did NOT
enumerate EventBridge sub-families originally. Like RDS, Step
Functions, and OpenSearch, this is post-hoc mapping because
the chain inventory already covers most of the compound surface
and the comparison story benefits from parity.

## Headline finding

EventBridge has **27 chains** spread across 9 functional
sub-families, AND — unlike Step Functions and OpenSearch —
it ships a ghost-reference chain. **EventBridge has zero
documented sub-family gaps.**

This is the first coverage map in the post-IAM series to land
without a documented gap. The reason is structural:
EventBridge's rule/target/pipe/scheduler/archive surface is
extensively composable (every rule has multiple targets, every
pipe has source + filter + enrichment + target, every scheduler
has invocation context + dead-letter queue), and the
chain-authoring trajectory has caught up to that breadth.

**EventBridge-touching chains shipping today: 27.** The
representative shapes:

- `chains/eventbridge_confused_deputy.yaml` —
  cross-account rule target + missing aws:SourceAccount /
  aws:SourceArn condition + service-principal trust pattern
- `chains/eventbridge_pipe_source_unsafe.yaml` —
  pipe source (SQS / Kinesis / DynamoDB Streams / MSK / MQ /
  self-managed Kafka) composition where source policy +
  pipe IAM + filter pattern misalign
- `chains/eventbridge_pipe_enrichment_overprivileged.yaml` —
  pipe enrichment Lambda has broader permissions than the
  source-to-target composition justifies
- `chains/eventbridge_scheduler_overprivileged.yaml` —
  EventBridge Scheduler execution role with broad
  cross-service permissions invoking targets the rule's
  intended scope doesn't justify
- `chains/eventbridge_scheduler_silent_loss.yaml` —
  Scheduler dead-letter-queue + flexible-time-window + retry
  composition producing invisible event loss
- `chains/eventbridge_replay_exfiltration.yaml` —
  archive replay + cross-account target + retention
  composition enabling data exfiltration via the archive
  surface
- `chains/eventbridge_archive_compliance_weak.yaml` —
  archive retention + encryption + cross-account-access
  composition for compliance-bound event data
- `chains/eventbridge_ghost_cascade.yaml` —
  rule/target/pipe references to deleted Lambda functions,
  SNS topics, SQS queues, Step Functions state machines,
  or IAM roles

## Sub-family coverage

| # | Sub-family | Status | Chains |
|---|---|---|---|
| 1 | Auth & cross-account (confused-deputy, connection auth, federation, policy) | covered | `eventbridge_confused_deputy`, `eventbridge_connection_auth_unsafe`, `eventbridge_federation_unsafe`, `eventbridge_policy_ungoverned` |
| 2 | Pipes (source unsafe, enrichment overprivileged, lifecycle) | covered | `eventbridge_pipe_source_unsafe`, `eventbridge_pipe_enrichment_overprivileged`, `eventbridge_pipe_lifecycle_decay` |
| 3 | Scheduler (overprivileged, silent loss, lifecycle, misfire) | covered | `eventbridge_scheduler_overprivileged`, `eventbridge_scheduler_silent_loss`, `eventbridge_scheduler_lifecycle_decay`, `eventbridge_schedule_misfire` |
| 4 | Delivery & failure paths (delivery blind/brittle, API destination failures, silent drop) | covered | `eventbridge_delivery_blind`, `eventbridge_delivery_brittle`, `eventbridge_apidest_failure_path`, `eventbridge_failure_path_weak`, `eventbridge_silent_drop` |
| 5 | Archive (replay exfiltration, compliance, lifecycle) | covered | `eventbridge_replay_exfiltration`, `eventbridge_archive_compliance_weak`, `eventbridge_archive_lifecycle_decay` |
| 6 | Schema & pattern governance | covered | `eventbridge_pattern_governance`, `eventbridge_schema_governance_weak` |
| 7 | Global endpoint & sub-product (cross-region failover surfaces) | covered | `eventbridge_globalendpoint_blind`, `eventbridge_subproduct_blind` |
| 8 | Operational visibility (destructive ops, governance, injection surface) | covered | `eventbridge_destructive_ops_blind`, `eventbridge_governance_decay`, `eventbridge_injection_surface` |
| 9 | Ghost-reference (rule/target/pipe references to deleted resources) | covered | `eventbridge_ghost_cascade` |

**Summary:** 9 sub-families, 9 covered, 0 gap.

## What's distinctive — first post-IAM map without a documented gap

Step Functions (8 covered + 1 ghost gap) and OpenSearch (9
covered + 1 ghost gap) both flagged ghost-reference as the
single documented gap. EventBridge ships `ghost_cascade`
already; the gap doesn't exist here.

**Pattern across the 4 post-IAM service maps:**

| Service | Sub-families | Gaps |
|---|---|---|
| RDS | 10 | 0 (1 partial) |
| Step Functions | 9 | 1 (ghost-reference) |
| OpenSearch | 10 | 1 (ghost-reference) |
| EventBridge | 9 | **0** |

EventBridge is the first to land both substantial chain
coverage AND zero gaps. The catalog's coverage trajectory is
catching up.

## What this comparison-story commit gains

`turbot/steampipe-mod-aws-compliance` has limited EventBridge
coverage relative to other AWS services — EventBridge's role
in compliance frameworks is less explicit than (say) S3 or
IAM, so framework benchmarks haven't aggressively expanded
the per-attribute control set. This is a case where Stave's
chain catalog leads framework-coverage by a wider margin
than usual.

What framework-mod controls structurally can't see, and what
EventBridge chains catch:

- **Confused-deputy via rule targets** — a cross-account rule
  invocation without aws:SourceAccount/Arn looks like
  3 separate framework attributes (cross-account target, no
  source-account condition, service-principal trust); the
  composition is the actual confused-deputy attack shape
- **Pipe enrichment overreach** — a pipe enrichment Lambda
  with broader IAM than the source-to-target composition
  needs is a privilege-escalation surface that the per-Lambda
  framework control on its own doesn't see (the Lambda's
  permissions are individually reasonable; the COMPOSITION
  with the pipe surface is the violation)
- **Scheduler silent loss** — Scheduler DLQ + flexible-time-
  window + retry composition produces invisible event loss
  for time-critical workflows; no per-attribute framework
  control names the conjunction
- **Archive replay exfiltration** — the archive surface
  permits replay of historical events to new targets;
  combined with cross-account target permission + retention
  policy, this becomes a data-exfiltration channel that no
  per-attribute control catches

These are the operational shapes EventBridge operators
recognize from incident analyses. The chain catalog names
them; the per-attribute framework catalog doesn't.

## What this commit ships

- **1 coverage document:** this file. Establishes the
  EventBridge compound surface as 27 chains across 9 covered
  sub-families with zero documented gaps.
- **0 net-new chains.** Existing coverage is comprehensive
  enough that this iteration is purely documentation.

## Audit notes

EventBridge is the first post-IAM service where the chain
catalog's compositional breadth matches the service's
intrinsic compositional surface. Step Functions came close
(8/9 with ghost gap); OpenSearch came close (9/10 with ghost
gap); EventBridge lands clean.

Two structural reasons:

1. **EventBridge's chain authors prioritized ghost-reference
   from the start.** The `eventbridge_ghost_cascade` chain is
   substantively older than the equivalent chains in newer
   services would be — EventBridge was an early target for
   the ghost-reference family because its rule-target
   indirection is exactly the ghost-prone shape.

2. **The service's surface is intrinsically compositional.**
   Rule → target, pipe → source/filter/enrichment/target,
   scheduler → invocation/DLQ/retry. Every primary entity is
   a composition. Authors naturally write chains that
   compose; the per-attribute framework catalog naturally
   lags because the per-attribute factoring is unnatural for
   this domain.

## Coverage maps shipped this session

  1. IAM             (Phase 1 — session start)
  2. VPC             (Phase 2)
  3. KMS             (Phase 3)
  4. S3              (Phase 4)
  5. Lambda          (Phase 5)
  6. ECS-EKS         (Phase 6)
  7. RDS             (bonus, mid-session)
  8. Step Functions  (later session)
  9. OpenSearch      (later session)
 10. EventBridge     (this commit)

**10 of 97 unique chain-prefix services** now have coverage
maps. Next-candidate services by chain count: ec2 (18),
cloudfront (16), apigw (16). The diminishing-marginal-value
boundary the session has been respecting starts to bite around
here — each subsequent map covers fewer chains than the prior
ones, and the comparison story already names 10 services.

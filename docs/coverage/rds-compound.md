# RDS compound coverage map

Seventh coverage map in the series (after IAM / S3 / VPC / KMS /
Lambda / ECS-EKS). The AWS compound control authoring plan
(`bizacademy/aws-compound-control-authoring-plan.md`) did NOT
enumerate RDS sub-families originally — RDS is being mapped
post-hoc because the chain inventory already covers most of the
obvious compound surface and the comparison story benefits from
parity with the other six services. This document audits what
ships today and surfaces any observation-contract gaps for
future iterations.

## Headline finding

RDS has **68 atomic controls** and (per the latest classifier
run) some number of compound-scope controls today — the
classifier reports per-control, not per-service, so the exact
RDS compound count is whatever `scope: compound` finds in
`controls/rds/`. The chain-level surface is larger and more
representative of the cross-resource attack patterns:

**RDS-touching chains shipping today: 19.** Each composes 2-4
atomic controls into a compound risk path. The representative
shapes:

- `chains/rds_public_exposure_path.yaml` — public + unencrypted
  + no deletion protection (sub-family 1)
- `chains/rds_snapshot_leakage.yaml` — shared / cross-env /
  public snapshot exposure (sub-family 2)
- `chains/rds_aurora_dr_gap.yaml` — Aurora secondary unencrypted
  or no cross-region recovery path (sub-family 3)
- `chains/rds_auth_weakness.yaml` — IAM auth off + default
  master user / publicly-fetchable Secrets Manager secret
  (sub-family 4)
- `chains/rds_audit_blind.yaml` — log export off + parameter
  group default + audit logging off (sub-family 5)
- `chains/rds_backup_failure.yaml` — backup retention + snapshot
  + recovery-time misconfiguration (sub-family 6)
- `chains/rds_proxy_insecure.yaml` — RDS Proxy without IAM auth
  or TLS (sub-family 7)
- `chains/rds_ghost_cascade.yaml` — dangling references to
  deleted KMS keys / parameter groups / option groups
  (sub-family 8, ghost-reference)

## Sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Public exposure + auth + encryption | covered | `rds_public_exposure_path`, `rds_plaintext_database` |
| 2 | Snapshot lifecycle (share / public / unencrypted) | covered | `rds_snapshot_leakage`, `rds_snapshot_unusable` |
| 3 | Aurora DR + cluster topology | covered | `rds_aurora_dr_gap`, `rds_aurora_single_point` |
| 4 | Authentication strength (IAM / password / Secrets) | covered | `rds_auth_weakness`, `rds_credential_lifecycle` |
| 5 | Audit + monitoring (logging + parameter group + events) | covered | `rds_audit_blind`, `rds_audit_incomplete`, `rds_monitoring_blind`, `rds_event_gap` |
| 6 | Backup + decommission + restore | covered | `rds_backup_failure`, `rds_decommission_incomplete` |
| 7 | Proxy + connection security | covered | `rds_proxy_failure`, `rds_proxy_insecure` |
| 8 | Ghost reference (deleted KMS / param / option groups) | covered | `rds_ghost_cascade` |
| 9 | Replication + read replica | partial | `rds_replica_exposure` — only the cross-region replica exposure case; multi-AZ replica + cross-account replica still atomic-only |
| 10 | Encryption (at-rest + in-transit + KMS-key-mgmt) | covered | `rds_encryption_weak` |

**Summary:** 9 covered, 1 partial, **0 observation-contract gaps**.

Compare to S3 (4 covered, 1 partial, **2 observation-contract
gaps**) — RDS's chain surface is more chain-shaped and less
extractor-shaped because RDS observations naturally carry the
cross-resource references the compound logic needs (snapshot →
KMS key, instance → parameter group, cluster → secondary, etc.)
without needing pre-computed booleans the way IAM does
(`identity.escalation.*`, `identity.blastradius.*`).

## What the comparison story gains from RDS coverage

`turbot/steampipe-mod-aws-compliance` covers RDS with framework
controls across CIS / PCI / HIPAA / NIST — every individual RDS
resource attribute the frameworks name has a corresponding
benchmark control. That coverage is mature and audit-grade. What
the framework-mod controls structurally can't see is the
compound shape: "public + unencrypted + no deletion protection
on the same instance" reads as 3 separate framework controls,
each correctly firing on its own resource attribute, with no
benchmark control that names the *conjunction* as the higher-
risk pattern. Stave's `rds_public_exposure_path` chain names
exactly that conjunction.

The two surfaces compose: framework mod for per-resource
compliance against named frameworks, Stave's RDS chains for the
compositional patterns operators recognize from breach analyses
(healthcare data leaks, financial-database compromises). Both
render in Powerpipe; both should run.

## What this commit ships

- **1 coverage document:** this file. Establishes the RDS
  compound surface as primarily chain-shaped (parallel to S3
  for non-extractor sub-families, and unlike IAM which is
  primarily observation-extractor-shaped).
- **0 net-new chains.** The 19 existing RDS chains already
  cover 9 of the 10 sub-families identified in this audit;
  the 10th (full replication coverage including multi-AZ +
  cross-account) is a follow-up for a future iteration if the
  audit-grade need surfaces.

## Audit notes

Sub-family 9 (replication) is flagged "partial" not "gap"
because the missing variants (multi-AZ replica configuration,
cross-account replica) are *authorable* against the existing
RDS observation contract — no new extractor fields required.
A future iteration could add 1-2 chains here without touching
the snapshot shape.

No observation-contract gaps were identified for RDS in this
audit. If the audit-grade need ever requires "RDS instance's
Secrets Manager secret was last rotated > N days ago AND the
instance has password authentication enabled" (a compound
across RDS + Secrets Manager + time), the relevant fact paths
already exist on the respective resources — the chain just
hasn't been authored yet.

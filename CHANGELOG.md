# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Architecture & Library

- **Chain-engine untangle: data types relocated to
  `internal/core/findings/`.** The chain-engine output types
  (`CompoundFinding`, `ExposureRank`, `ScoreBreakdown`,
  `ThresholdItem` / `ThresholdItems` / `ThresholdStatus` /
  `ThresholdSummary` / `ThresholdFilter` and constants) moved
  out of `internal/core/evaluation/risk/` into a new leaf
  package `internal/core/findings/`. `report/` no longer
  imports `risk/`; the structural cycle that prevented the
  chain engine from being separable is gone. `risk/` retains
  producer logic (`DetectChains`, `RankExposures`, formula
  helpers, threshold pipeline). The 13-commit sequence is
  tracked in `may8.md`; the final-cleanup commit deleted all
  transitional aliases in `risk/`. Nothing in the user-facing
  YAML or output shape changed — code-organization win that
  unblocks future chain-engine substitution.

- **Public sentinel errors for facade-bar commands:
  `stave.ErrInvalidInput` and `stave.ErrFailingTests`.** Commands
  that have migrated to the `pkg/stave` facade cannot import
  `internal/cli/ui` per their architecture tests. The two
  public sentinels in `pkg/stave/errors.go` give them a way
  to communicate "this was a user-input error" (→ exit code 2)
  and "tests completed but some failed" (→ exit code 3) without
  violating the facade rule. Wrap with
  `fmt.Errorf("... : %w", stave.ErrInvalidInput)`. The
  exit-code mapping happens in `internal/cli/ui.ExitCode` via
  `errors.Is`. Reusable by every future facade-bar migration.

- **`pkg/stave` facade migration: 6 commands at the bar.**
  `cmd/stave-mcp/`, `cmd/gaps/`, `cmd/readiness/`,
  `cmd/score/`, `cmd/exportinvariants/`, and `cmd/test/` now
  import only `pkg/stave`, `cmd/cmdutil`, cobra, and the
  standard library. Each has an `architecture_test.go` that
  fails the build if any file in the command's directory
  reintroduces an `internal/*` import. New public helpers
  landed in `pkg/stave/` to enable the migrations:
  `LoadAssessment`, `LoadAssessments`, `SortAssessmentsByTime`,
  `BuiltinChainBudget`, `ParseWeights`, `RunControlTests`,
  plus the type aliases `ScoreMover`, `TrendPoint`,
  `TestResult`, `TestCaseResult`, `TestSummary`. Future
  facade-bar migrations get correct exit codes and shared
  helpers for free. Migration plan + tracker:
  `docs/architecture/pkg-stave-facade.md`.

### Added

- **Phase 7 — CIA-derived intensional detection (G0–G6 +
  closeout candidates B and D).** Soufflé Datalog reasoning
  over the IAM access graph that detects Confidentiality and
  Integrity violations *intensionally* — derived from
  reachability + sensitivity, not from a pattern catalog.
  Catches the **novel violation class** that pattern-based
  scanners miss by construction. Lives at
  `reasoning/souffle/iam/` (schema.dl + rules.dl +
  action_classes.dl + Go extractor / validator / findings
  emitter). G3 added the authorization model
  (`docs/authorization-model.md` + `data/stave-authorization.yaml`
  default with Owner/Team + DataClassification PII/PHI/PCI).
  G4–G5 added `violation_c` and `violation_i` queries that
  emit PostureFindings with `control_id` =
  `CIA.C.UNAUTHORIZED_READ` / `CIA.I.UNAUTHORIZED_WRITE`.
  G6 triaged the first round of novel violations and added
  Shape-B fixtures (Capital One pattern + Cognito-anon
  pattern). Closeout D shipped Powerpipe CIA rendering at
  `projects/powerpipe-mod-stave/benchmarks/cia_findings.pp`. Full
  rationale + structural finding ("~95% of catalog fires on
  Shape-A escalation booleans, not access-graph edges") in
  `docs/coverage/cia-novel-violations.md` +
  `aws-compound-authoring.md` status marker. Phase 7 is the
  structural defensibility tier the substrate framing
  (projects/stave-guide/explanation/reasoning-contract.md) points at —
  the CIA intensional layer is what no framework-coverage
  mod can replicate.

### Changed

- **`docs/comparison/aws-compliance-mod.md` refreshed against
  current catalog (2026-05-26).** Numbers: 95.5% atomic
  (3,784 of 3,962) / 4.5% compound (178 of 3,962) — was 96/4
  in the previous snapshot. Ghost-reference controls: 104
  across 18 AWS services with per-service breakdown — was
  "~100 across 11 services." Footnote now includes total
  catalog size (3,962), compound chain count (597), and
  asset-schema count (109); explicit verification date;
  honest framing on the AWS compound authoring plan target
  (Phase 1 + Phase 7 shipped, ~8.6% headline target wasn't
  met because catalog grew faster than compound — see
  `may8.md`). Pointer added to the substrate-vs-implementation
  framing that reduces the foundational weight on the
  share-percentage argument.

- **Lambda-2 — environment-variable security, KMS deepening,
  and Secrets Manager integration (6 new controls, 3 chains).**
  Second Lambda gap-closure batch. Closes the
  credential-handling surface around Lambda environment
  variables. Spec asked for ~8 controls; one duplicated
  `CTL.LAMBDA.ENV.ENCRYPT.001` (which already covers
  AWS-managed-key vs CMK encryption), so 6 distinct
  additions shipped. KMS (1):
  `ENV.KMS.EXTERNAL` (function uses a KMS key owned by an
  external AWS account; the external owner can disable
  the key, schedule deletion, or revoke decrypt rights and
  break the function with no recourse on this side; same
  pattern as CTL.S3.ENCRYPT.KMS.OWNERSHIP.001 and the RDS
  external-key concept, high). Secrets management (3):
  `SECRETS.NOTMANAGED` (raw credentials in env vars rather
  than Secrets Manager / SSM SecureString references; four
  exposure problems compound — disclosure surface, version
  persistence, audit invisibility, rotation friction;
  distinct from CTL.LAMBDA.ENV.SECRETS.001 which detects
  the pattern, this control checks for the management
  alternative, high), `SECRETS.BROKEN.REF` (env var
  references a Secrets Manager ARN or SSM parameter the
  execution role cannot fetch; runtime AccessDeniedException
  on every cold start; cross-resource reasoning joins env
  references against role policy grants, high),
  `SECRETS.SSM.INSECURE` (env var references an SSM
  String-typed parameter holding a credential; plaintext
  at rest, single-action gating, no kms:Decrypt, no
  per-fetch audit, medium). Env var deepening (2):
  `ENV.VISIBLE.VERSIONS` (older published versions retain
  immutable env-block snapshots that diverge from the
  current version; credentials in past env blocks remain
  readable forever via lambda:GetFunction on the
  version-qualified ARN, medium), `ENV.EXCESSIVE` (env-var
  count exceeds the audit threshold; configuration
  sprawl drives audit, rotation, and disclosure costs
  linearly, low). Chains: `lambda_credential_exposure`
  (existing CTL.LAMBDA.ENV.SECRETS.001 + SECRETS.NOTMANAGED
  + existing CTL.LAMBDA.ENV.ENCRYPT.001 — credentials in
  env vars on multiple defense dimensions failing at
  once), `lambda_secrets_broken` (BROKEN.REF OR
  SSM.INSECURE OR Lambda-1's GHOST.KMS — any single
  break in the secrets-fetch chain at runtime),
  `lambda_credential_history` (VISIBLE.VERSIONS + existing
  CTL.LAMBDA.ENV.SECRETS.001 — credential patterns now
  AND immutable version snapshots that retain past ones).
  18 e2e fixtures including `secrets-notmanaged-multi-fail`
  (4 raw credential keys at once) and
  `secrets-broken-ref-wrongscope-fail` (role grants
  GetSecretValue on an old version of the secret while
  the env var references the new one). 6 triage overrides.
  Lambda secrets coverage: pattern detection only →
  comprehensive (management method + key quality +
  permission alignment + storage type + version
  history + sprawl).
- **Lambda-1 — ghost references, function URL security,
  and resource policy deepening (6 new controls, 4 chains).**
  First Lambda gap-closure batch. Extends the
  ghost-reference family to serverless compute.
  Spec asked for ~10 controls; four duplicated existing
  catalog entries (CTL.LAMBDA.URL.AUTH.001 covered
  URL.NOAUTH; CTL.LAMBDA.URL.CORS.001 covered URL.CORS;
  CTL.LAMBDA.LAYER.GHOST.001 covered GHOST.LAYER;
  CTL.LAMBDA.TRIGGER.GHOST.001 covered GHOST.ESM), so 6
  distinct additions shipped. Ghost references (4):
  `GHOST.ROLE` (function references a deleted execution
  role; cannot assume the role on invocation, every
  trigger fires into total failure while the console
  reads "Active," critical), `GHOST.VPC`
  (VPC-configured function references a deleted subnet
  or SG; ENI creation fails on cold start while warm
  invocations continue, producing the hardest-to-
  diagnose intermittent-failure pattern, high),
  `GHOST.KMS` (deleted or pending-deletion KMS key for
  environment-variable encryption; KMS:Decrypt fails on
  every cold start before the handler runs, high),
  `GHOST.DLQ` (DLQ ARN points at a deleted queue or
  topic; failed asynchronous events vanish silently —
  no error propagation, no notification, the
  reprocessing-from-DLQ workflow has no input, high;
  distinct from CTL.LAMBDA.DLQ.001 which catches the
  "no DLQ at all" case). Resource policy (2):
  `POLICY.CROSSACCOUNT` (cross-account grant without
  aws:PrincipalOrgID, aws:SourceAccount, or
  aws:SourceArn condition; compromise blast radius
  equals the entire named external account, high),
  `POLICY.ACCUMULATED` (resource policy past the
  audit threshold; lambda:AddPermission accretes
  statements that are rarely removed and the function's
  invocation surface becomes unauditable, medium).
  Chains: `lambda_ghost_cascade` (≥2 of role / VPC /
  KMS / DLQ ghosts plus the existing
  CTL.LAMBDA.LAYER.GHOST.001 — systematic
  decommissioning failure, threshold 2, compound
  critical), `lambda_public_exposure` (any of existing
  CTL.LAMBDA.URL.AUTH.001, CTL.LAMBDA.URL.CORS.001, or
  CTL.LAMBDA.INVOKE.PUBLIC.001 — threshold 1, fast-
  firing on any single public path), `lambda_invocation_sprawl`
  (POLICY.ACCUMULATED + (POLICY.CROSSACCOUNT OR existing
  CTL.IAM.ESCALATE.EDITLAMBDA.001) — unauditable plus
  unscoped or further-expandable), `lambda_silent_failure`
  (GHOST.DLQ OR existing CTL.LAMBDA.TRIGGER.GHOST.001 —
  threshold 1, both cause silent data loss). 15 e2e
  fixtures including 3 variants: ghost-role-active-fail
  (function with active triggers receiving 50 events/min
  while every invocation fails), ghost-vpc-sgonly-fail
  (subnet-only-deleted vs SG-only-deleted distinction),
  and ghost-dlq-sns-fail (DLQ pointing at deleted SNS
  topic vs SQS). 6 triage overrides. Ghost reference
  total in catalog: 48 → 54.
- **RDS-6 — Aurora-specific, HA, and lifecycle controls
  (8 new controls, 3 chains).** Sixth and final RDS
  gap-closure batch. Closes the Aurora-specific
  surface (cluster topology, MySQL backtrack, serverless
  v1, Global Database secondary encryption), the HA
  surface beyond Multi-AZ (read-replica AZ placement,
  read-replica config drift), and the instance-lifecycle
  surface (storage type, instance generation). All 8
  controls net-new — no overlap with existing RDS
  catalog. Aurora (4): `AURORA.SINGLEINSTANCE` (Aurora
  cluster with no reader has worse availability than
  Multi-AZ standard RDS — must provision a fresh
  instance on writer failure where Multi-AZ RDS has a
  pre-warmed standby, high), `AURORA.BACKTRACK` (Aurora
  MySQL without backtrack — recovery from operator-
  caused destructive incidents reverts to multi-hour
  snapshot-restore-and-cutover; Aurora MySQL only,
  PostgreSQL gated out, medium), `AURORA.SERVERLESS.V1`
  (cluster on Aurora Serverless v1 with cold-start
  cliff plus missing IAM auth / Performance Insights /
  read replicas / Global DB; v1 EOL announced,
  medium), `AURORA.GLOBAL.UNENCRYPTED` (Global Database
  secondary cluster unencrypted — primary's
  cross-region replication becomes the path that
  takes data out of encrypted storage, high). HA (2):
  `HA.REPLICA.SAMEAZ` (read replica in same AZ as
  primary — AZ event takes both offline; the most
  common AWS outage class is single-AZ, medium),
  `HA.REPLICA.CONFIG` (replica security configuration
  drifts from primary — broader SG, weaker parameter
  group, public flag mismatch — replica becomes the
  soft target for the same data, high). Lifecycle (2):
  `LIFECYCLE.STORAGETYPE` (gp2 instead of gp3 —
  burst-credit-exhaustion latency cliffs misattributed
  to application bugs, low), `LIFECYCLE.GENERATION`
  (db.m4 / db.r4 / db.t2 / db.m3 — Xen-era hypervisor
  surface inherits the XSA CVE class same as
  CTL.EC2.NITRO.001 catches on EC2, plus an
  instance-family retirement deadline, medium).
  Chains: `rds_aurora_single_point` (single-instance
  Aurora + no cluster deletion protection — uses
  existing CTL.RDS.CLUSTER.DELETION.PROTECT.001;
  cluster is one API call from irrecoverable, threshold
  2, compound critical), `rds_replica_exposure`
  (REPLICA.CONFIG drift OR REPLICA.SAMEAZ; threshold 1
  fast-firing on any replica defect),
  `rds_aurora_dr_gap` (GLOBAL.UNENCRYPTED OR no
  cross-region path — uses RDS-5's
  CTL.RDS.BACKUP.CROSSREGION.001). 19 e2e fixtures
  including 4 engine-gate variants
  (singleinstance-postgres-fail asserts both Aurora
  engines are caught, backtrack-pg-pass asserts the
  PostgreSQL gate skips the control), and a 3-diff
  REPLICA.CONFIG variant exercising compound drift.
  8 triage overrides. Final RDS batch; the 6
  batches together added 45 net-new RDS controls.
- **RDS-5 — backup deepening, cross-region DR, and
  snapshot sharing security (7 new controls, 3 chains).**
  Fifth RDS gap-closure batch. Closes the data-
  resilience and snapshot-boundary surface that the
  earlier RDS batches did not reach. Spec asked for
  ~8 controls; one duplicated `CTL.RDS.ENCRYPT.BACKUP.001`
  (RDS-1's automated-backup encryption check), so 7
  distinct additions shipped. Backup (3):
  `BACKUP.RETENTION.COMPLIANCE` (compliance-tagged
  instance with retention below the framework floor —
  PCI 1y, HIPAA 6y, SOX 7y; fires only when the
  obligation is present, high), `BACKUP.CROSSREGION`
  (no cross-region recovery path of any kind — no
  AWS Backup cross-region copy, no automated-backup
  replication, no cross-region read replica; regional
  outage = total data unavailability, medium),
  `BACKUP.CROSSREGION.ENCRYPT` (cross-region copy
  unencrypted at destination because copy operation
  omitted `--kms-key-id`; source-region audit reads
  encrypted but the off-region copy is plaintext,
  high). Snapshot sharing (4):
  `SNAPSHOT.UNENCRYPTED.SHARED` (snapshot shared with
  named accounts in plaintext; receiving account
  restores and reads everything, distinct from
  CTL.RDS.SNAPSHOT.PUBLIC.001 which catches `all`,
  high), `SNAPSHOT.CROSSENV` (production-tagged
  snapshot shared with non-production account; same
  pattern as CTL.EC2.EBS.CROSSENV.SNAPSHOT.001 in
  the database domain, high), `SNAPSHOT.AWSKEY.SHARED`
  (snapshot encrypted with aws/rds is shared
  cross-account; the share appears successful but
  restore fails with KMS access-denied — operational
  failure disguised as successful sharing, surfacing
  during DR rehearsals and audit-copy workflows,
  medium), `SNAPSHOT.STALE` (manual snapshot > 365
  days old; cost accumulation plus retention vs
  deletion-policy gap for GDPR / HIPAA endpoints,
  low). Chains: `rds_backup_failure` (existing
  ENCRYPT.BACKUP + (no cross-region OR retention
  below compliance) = backup posture broken on
  multiple dimensions), `rds_snapshot_leakage`
  (UNENCRYPTED.SHARED OR CROSSENV OR existing
  SNAPSHOT.PUBLIC; threshold 1, fast-firing for
  any sharing-boundary breach), `rds_snapshot_unusable`
  (AWSKEY.SHARED OR CROSSREGION.ENCRYPT off; backup
  exists but is either inaccessible or insecure).
  17 e2e fixtures including a no-obligation gate
  variant (RETENTION.COMPLIANCE asserts non-regulated
  workloads are not flagged), an automated-snapshot
  gate variant (STALE asserts the type-gate skips
  RDS-managed automated snapshots), and a compound
  CROSSENV-plus-unencrypted variant. 7 triage
  overrides. RDS backup / snapshot coverage:
  partial → comprehensive.
- **RDS-4 — authentication, Secrets Manager integration,
  and RDS Proxy security (6 new controls, 3 chains).**
  Fourth RDS gap-closure batch. Closes the credential-
  lifecycle and Proxy-security surface that RDS-1/2/3 did
  not cover. Spec asked for ~8 controls; three duplicated
  existing catalog entries (CTL.RDS.IAMAUTH.001 covered
  IAM.ENFORCE; CTL.SECRETS.ROTATION.001 covered the
  generic SM rotation case which the proposed RDS-specific
  variant subsumes; CTL.SECRETSMANAGER.POLICY.PUBLIC.001
  covered SECRET.POLICY's public-policy core), so 6
  distinct additions shipped. Authentication (3):
  `AUTH.MASTERUSER` (master username matches a well-known
  default — admin / root / postgres / sa / master /
  dbadmin / mysql / oracle — handing the attacker half
  the credential pair for free; remediation requires
  instance recreation since engines have no master-
  rename, medium), `AUTH.MASTERPASSWORD.AGE` (master
  password not rotated within 90 days; long-lived admin
  credentials accumulate exposure across shell history,
  config repos, build artifacts, and rotated-out team
  members, high), `SECRET.EXISTS` (database credentials
  not in Secrets Manager — therefore in config files,
  ECS task definitions, Lambda env vars, SSM Parameter
  Store as String, or hardcoded; multiple copies, no
  rotation, no audit, high). RDS Proxy (3): `PROXY.IAM`
  (Proxy does not require IAM auth on client connections;
  applications still hold the database password defeating
  the centralization that motivated the Proxy, medium),
  `PROXY.TLS` (Proxy backend connection not TLS-required;
  same false-encryption pattern as CDN-to-S3-origin and
  Cloudflare Flexible mode — client side TLS terminates
  at the Proxy and the Proxy-to-DB hop carries credentials
  and query data plaintext through the VPC where any
  same-VPC observer reads them, high), `PROXY.EXPOSURE`
  (Proxy SG permits ingress beyond app tier; the Proxy's
  own auth/TLS defenses fire against every reachable
  principal instead of the curated app tier, medium).
  Chains: `rds_credential_lifecycle` (no SM secret +
  (no rotation OR stale master password) — uses existing
  CTL.SECRETS.ROTATION.001), `rds_auth_weakness` (no IAM
  auth + (predictable username OR public secret policy)
  — uses existing CTL.RDS.IAMAUTH.001 +
  CTL.SECRETSMANAGER.POLICY.PUBLIC.001), `rds_proxy_insecure`
  (no backend TLS + (no IAM OR broad SG)). 14 e2e fixtures
  including engine-specific MASTERUSER variants
  (admin / postgres) and a Proxy false-TLS variant
  asserting client-side TLS does not redeem backend
  plaintext. 6 triage overrides. RDS Proxy coverage:
  1 (ghost) → 4 controls. RDS auth coverage: partial →
  comprehensive.
- **RDS-3 — ghost references and orphaned resources
  (8 new controls, 3 chains).** Third RDS gap-closure
  batch. Extends Stave's ghost-reference pattern
  (cross-inventory existence checks) to the database
  domain. All 8 controls net-new — no overlap with
  the existing RDS catalog. Ghost references (6):
  `GHOST.SUBNETGROUP` (DB subnet group references a
  deleted subnet → Multi-AZ failover places standby in
  a non-existent subnet during the AZ outage that
  triggered the failover, high), `GHOST.PARAMGROUP`
  (instance references a deleted parameter group →
  silent regression to permissive engine defaults
  while the console reads healthy, high),
  `GHOST.OPTIONGROUP` (deleted option group → Oracle
  TDE / SQL Server audit / S3 integration silently
  disable, medium), `GHOST.EVENTSNS` (event
  subscription targets a deleted SNS topic → events
  fire, notifications drop into the void; same pattern
  as CTL.CLOUDWATCH.ALARM.GHOST.001 on the RDS side,
  high), `GHOST.PROXYSECRET` (RDS Proxy references a
  deleted Secrets Manager secret → DELAYED failure on
  pool refresh hours after the secret deletion,
  critical — the only critical in the batch and
  the most dangerous ghost pattern in the catalog),
  `GHOST.SG` (instance attaches a deleted security
  group → undefined network policy at next
  modification; distinct from CTL.VPC.SG.GHOST.001
  which catches the SG-rule side, high). Orphaned
  resources (2): `ORPHAN.SNAPSHOT` (snapshot whose
  source instance has been deleted → full database
  contents readable to any principal with
  rds:RestoreDBInstanceFromDBSnapshot rights, medium),
  `ORPHAN.SUBNETGROUP` (DB subnet group with zero
  associated instances → cleanup-incomplete signal,
  pins underlying VPC subnets, low). Chains:
  `rds_ghost_cascade` (≥2 of subnetgroup / paramgroup
  / eventsns / sg ghosts = systematic decommissioning
  failure), `rds_proxy_failure` (proxy secret OR
  proxy SG ghost = either alone causes Proxy failure
  with delayed surfacing), `rds_decommission_incomplete`
  (orphan snapshot + (orphan subnetgroup OR ghost
  paramgroup) = data + config + settings all
  un-cleaned). 19 e2e fixtures including
  proxysecret-active-fail (delayed failure with
  active connections), subnetgroup-allghost-fail
  (complete placement failure), and
  orphan-snapshot-unencrypted-fail (compound). 8
  triage overrides. Ghost reference total in the
  catalog: 42 → 48.
- **RDS-2 — logging deepening, CloudWatch alarms, and event
  subscriptions (10 new controls, 3 chains).** Second RDS
  gap-closure batch. Closes the operational-monitoring
  surface that RDS-1 (TLS / encryption / parameter group)
  did not reach. All 10 planned controls were net-new
  after dedup against existing CTL.RDS.MONITORING.001
  (Enhanced Monitoring boolean), CTL.RDS.PERFORMANCE.INSIGHTS.001
  (PI + KMS boolean), CTL.RDS.EVENTS.001 (generic critical
  subscription boolean), CTL.RDS.LOG.001 (audit boolean),
  and CTL.RDS.CLUSTER.LOGGING.001 (Aurora cluster scope) —
  the new controls deepen those areas with specific
  configuration checks. Monitoring (4): `MONITORING.INTERVAL`
  (Enhanced Monitoring interval > 15s collapses short-event
  visibility, medium), `PERFINSIGHTS.RETENTION` (PI retention
  below 7-day free-tier baseline collapses trend / regression
  / forensics window, low), `ALARM.CPU` (no CPUUtilization
  alarm; spike from runaway query, connection storm, SQL-
  injected cryptominer, or DoS detected via app symptom
  instead, medium), `ALARM.CONNECTIONS` (no
  DatabaseConnections alarm; Lambda cold-start storm
  saturates max_connections without warning, medium).
  Alarms (2): `ALARM.STORAGE` (no FreeStorageSpace alarm;
  read-only transition arrives without warning and writes
  fail mid-transaction, high — only high-severity alarm
  control), `ALARM.REPLICATION` (no ReplicaLag alarm on
  instances with read replicas; stale-read incidents
  present as application data-quality bugs). Logging (2):
  `LOG.RETENTION` (CloudWatch log group retention below
  framework floor; PCI 1y, HIPAA 6y, SOX 7y, audit data
  unrecoverable, medium), `LOG.SLOWQUERY` (slow-query log
  disabled; performance + SQL-injection + DoS signals
  collapse to a single dull "slow database" symptom,
  medium). Events (2): `EVENTS.DELETION` (no deletion
  event subscription; pairs with deletion protection as
  detective control when preventive control is bypassed
  by drift, high), `EVENTS.SECURITY` (no security-event
  subscription; SG / parameter / configuration / certificate
  changes detected only via CloudTrail mining, medium).
  Chains: `rds_monitoring_blind` (no CPU + (no storage OR
  no connections) = three primary load signals
  unmonitored), `rds_audit_incomplete` (slow-query off +
  (short retention OR no export) = audit chain broken at
  multiple points), `rds_event_gap` (no deletion-event +
  (no security-event OR no deletion protection) = change
  detection plus preventive control both gone). 22 e2e
  fixtures including engine variants (slow-query MySQL +
  PostgreSQL pass) and scope-gate variants (replication
  alarm standalone pass for instances without replicas).
  10 triage overrides. RDS monitoring coverage: partial →
  comprehensive.
- **RDS-1 — TLS, encryption, and parameter-group security
  (6 new controls, 3 chains).** First RDS gap-closure
  batch. Closes the database-engine-configuration
  surface that VPC, IAM, and generic-encryption controls
  do not reach. Prompt spec asked for ~10 controls; four
  turned out to duplicate existing ones (`CTL.RDS.SSL.001`
  and `CTL.RDS.SSL.ENFORCE.001` covered TLS.ENFORCE;
  `CTL.RDS.PARAM.GROUP.001` covered PARAM.DEFAULT;
  `CTL.RDS.LOG.001` covered PARAM.LOGGING;
  `CTL.RDS.PERFORMANCE.INSIGHTS.001` covered
  ENCRYPT.PI), so shipped 6 distinct additions.
  TLS (2): `TLS.VERSION` (instance accepts TLS 1.0/1.1
  → sub-modern transport encryption + downgrade path
  attacks, medium), `TLS.CACERT` (outdated AWS-issued CA
  certificate → pending TLS connection failure cliff at
  CA rotation, with emergency-mode disabled-verification
  regression risk, medium). Encryption (2):
  `ENCRYPT.CMK` (instance encrypted with aws/rds shared
  key instead of CMK → no disable, no key-policy audit,
  no cross-account snapshot share, medium),
  `ENCRYPT.BACKUP` (automated backups stored
  unencrypted while live instance reports encrypted →
  recoverable plaintext copy of the database
  unnoticeable in console, high). Parameter group (2):
  `PARAM.PASSWORDHASH` (PostgreSQL password_encryption
  set to md5 instead of scram-sha-256 → unsalted
  catalog-level password compromise via public rainbow
  tables, medium), `PARAM.LOGEXPORT` (instance does
  not export logs to CloudWatch → audit data invisible
  to centralized logging, alerting, and SIEM, distinct
  from existing CTL.RDS.CLUSTER.LOGGING.001 which
  covers Aurora clusters, high). Chains:
  `rds_plaintext_database` (TLS not enforced + at-rest
  not encrypted OR backup not encrypted = plaintext
  reachable through more than one channel),
  `rds_audit_blind` (audit logging off + log export
  off OR default parameter group = compromise leaves
  no record of data accessed), `rds_encryption_weak`
  (aws/rds key + deprecated TLS OR md5 password hash
  = encryption that does not survive serious adversary
  review). 13 e2e fixtures (12 base pass/fail +
  passwordhash-mysql-pass variant asserting the control
  is a no-op on non-PostgreSQL engines). 6 triage
  overrides. RDS parameter-level security: 0 → 4
  controls (combined with existing PARAM.GROUP / LOG).
- **EC2-6 — key pair lifecycle and remaining EC2 gaps
  (6 new controls, 2 chains).** Final EC2 gap-closure
  batch. Closes the API-observable key-pair surface
  (most key-pair gaps — password auth, root login,
  authorized_keys, host key verification — are OS-level
  and not visible from the EC2 / SSM API; this batch
  covers what is visible) plus addressable LT/ASG drift.
  Key pair lifecycle (3): `KEYPAIR.SHARED` (key pair
  shared across > 5 instances → blast radius of one
  leaked private half is N instances and rotation is
  rarely paid in practice, medium), `KEYPAIR.NOKEY.SSHOPEN`
  (no key pair attached but SG allows port 22 →
  ambiguous SSH plane, either brute-forceable, invisibly
  authorized post-launch, or gratuitously exposed,
  medium), `KEYPAIR.SSM.PREFERRED` (SSM-managed instance
  also has key pair + SG SSH → redundant attack surface
  when SSM provides better auth, audit, and revocation,
  low). Launch template / ASG drift (3):
  `LT.VERSION.STALE` (LT default version != latest →
  authored hardening not in effect; new launches use
  older config, medium), `ASG.LAUNCHCONFIG` (ASG on
  legacy launch configuration → no IMDSv2 enforcement,
  no version history, no mixed-instance support, medium),
  `LT.PUBLICIP` (LT forces AssociatePublicIpAddress=true
  → overrides subnet architecture, instances designed for
  private subnets launch internet-facing, high). Chains:
  `ec2_ssh_attack_surface` (SHARED + NOKEY-SSHOPEN +
  broad SG CIDR = high blast radius AND easy to reach),
  `ec2_lt_security_drift` (LT stale + forces public IP
  + ghost AMI = template is the source of truth and
  multiple drift signals reproduce on every launch).
  13 e2e fixtures (12 base pass/fail + extreme-50-instance
  variant for KEYPAIR.SHARED). 6 triage overrides.
  EC2 gap closure complete: 6 batches, 47 net-new
  controls (≈8 per batch; spec asked for ~58 but
  duplicates against existing catalog dropped each
  batch).
- **EC2-5 — trusted platform and network exposure deepening
  (7 new controls, 3 chains).** Fifth EC2 gap-closure
  batch. Opens the trusted-platform domain (was 0
  controls) and deepens network exposure beyond the
  security-group surface that VPC-1 / VPC-7 covered.
  Prompt spec asked for ~8 controls; one turned out to
  duplicate an existing one (`CTL.EC2.NETWORK.DIRECT.001`
  covered DIRECTEXPOSE), so shipped 7 distinct additions.
  Trusted platform (4): `NITRO` (Xen-based instance type
  inherits the historical Xen XSA CVE class and is gated
  out of Nitro-only hardening features, medium),
  `SECUREBOOT` (UEFI-capable instance without Secure Boot
  → bootkit / rootkit persistence below the OS-level
  detection threshold, medium), `NITROTPM` (NitroTPM-
  capable instance without it → no hardware-rooted
  attestation, EBS-detach-and-read attacks remain viable,
  low), `TENANCY.SENSITIVE` (compliance-tagged workload
  on shared tenancy → contractual / framework gap even
  when technical isolation is sufficient, medium).
  Network exposure deepening (3): `NETWORK.DUALHOMED`
  (instance with ENIs in two security zones IS the bridge
  between them — architectural segmentation bypass with
  no audit trail, high), `NETWORK.SRCDSTCHECK` (source/
  destination check disabled on a non-NAT/VPN/appliance
  → instance can route, proxy, and address-spoof at
  kernel level, high), `NETWORK.MULTIPLE.SG` (instance
  with > 5 SGs has effective rule set as union of
  hundreds of rules, exceeding practical reviewability,
  medium). Chains: `ec2_hardware_security_gap` (non-Nitro
  + Secure Boot off OR sensitive-on-shared-tenancy =
  layered hardware defenses removed),
  `ec2_network_pivot` (DUALHOMED OR SRCDSTCHECK = each
  alone makes the instance a kernel-level pivot point),
  `ec2_direct_exposure` (DIRECT + MULTIPLE.SG +
  HIGHPORTS = no upstream LB protection AND unauditable
  local rules AND known-risky services exposed). 18 e2e
  fixtures (12 base pass/fail + 6 variants:
  nitro-t2-fail, dualhomed-3tier-fail, srcdstcheck-nat-pass,
  tenancy-nonsensitive-pass + 2 redundant pass cases).
  7 triage overrides. Trusted platform: 0 → 4 controls.
- **EC2-4 — instance lifecycle and orphaned resources
  (6 new controls, 3 chains).** Fourth EC2 gap-closure
  batch. Closes the post-termination decommission-leak
  surface and the long-lived-instance retirement surface.
  Prompt spec asked for ~8 controls; two turned out to
  duplicate existing ones (`CTL.EC2.INSTANCE.AGE.001`
  covered RUNNING.AGED; `CTL.CLOUDWATCH.ALARM.GHOST.001`
  covered GHOST.ALARM), so shipped 6 distinct additions.
  Instance lifecycle (2): `INSTANCE.STOPPED.AGED` (stopped
  > decommission threshold accumulates EBS, ENIs, IAM
  attachments, all readable on a single Start, medium),
  `INSTANCE.EOL` (running on retired instance family →
  capped security primitives now and unrecoverable on next
  AZ failover, medium). Orphaned resources (3):
  `ENI.ORPHAN` (detached > threshold → IP/SG-quota leak,
  attach-back lateral movement, low), `SNAPSHOT.AMI.DEREGISTERED`
  (AMI deregistration leaves snapshots → indefinite
  historical-state retention readable to anyone with
  CreateVolume, medium), `KEYPAIR.ORPHAN` (key pair with
  no current users → persistent SSH backdoor potential
  via re-launched AMIs, medium). Resource-side ghost (1):
  `ROUTE53.HEALTHCHECK.GHOST` (health check whose target
  was deleted → alert fatigue + cross-tenant probe risk
  on reissued IPs, low) — resource-side twin of
  CTL.ROUTE53.DANGLING (DNS-record side). Chains:
  `ec2_dormant_attack_surface` (long-stopped instance +
  orphan ENI/keypair = forgotten access path),
  `ec2_decommission_incomplete` (snapshot + ENI + keypair
  artifacts together prove cleanup workflow stopped after
  AMI deregistration), `ec2_permanent_vulnerability`
  (EOL family + aged + unmanaged = no remediation pipeline
  before the EOL deadline). 12 e2e fixtures. 6 triage
  overrides.
- **EC2-1 — launch template ghost references and AMI security
  (6 new controls, 3 chains).** First EC2 gap-closure
  batch. Extends the ghost-reference pattern to launch
  templates — Stave's architectural moat now covers the
  compute supply chain in addition to S3, IAM, KMS, VPC,
  EventBridge, CloudWatch, Route53, GitHub CODEOWNERS, and
  ELB. Prompt spec asked for ~10 controls; three turned out
  to duplicate existing ones (`CTL.EC2.AMI.GHOST.001` covered
  LT.GHOST.AMI; `CTL.EC2.AMI.CURRENCY.001` covered both
  AMI.STALE and AMI.DEPRECATED), so shipped 6 distinct
  additions. Launch-template ghosts (4): `LT.GHOST.SG`
  (deleted SG → silent posture downgrade to default SG when
  instances launch, high), `LT.GHOST.KEYPAIR` (deleted key
  pair → unmanageable instance, medium), `LT.GHOST.SUBNET`
  (deleted subnet → AZ redundancy loss or launch failure,
  high), `LT.GHOST.PROFILE` (deleted instance profile →
  runtime IAM credential failure invisible to EC2 health
  checks, high). AMI security (2): `AMI.UNTRUSTED` (AMI from
  account outside the trusted publisher set — supply-chain
  compromise via base image, high), `AMI.ENCRYPTION` (AMI
  EBS snapshots not encrypted — data-at-rest exposure on
  every instance launched from it, medium). Chains:
  `ec2_lt_ghost_cascade` (multiple LT ghost references
  indicate systematic decommissioning failure),
  `ec2_ami_supply_chain` (untrusted AMI + stale or
  unencrypted), `ec2_scale_out_failure` (deregistered AMI OR
  stale AMI — both compromise auto-scaling safety). 13 e2e
  fixtures (12 base + amazon-pass variant for AMI.UNTRUSTED
  asserting Amazon-published AMIs are trusted). 6 triage
  overrides. Ghost reference total across catalog: 37 → 41.
  Docs and README regenerated (1392 controls).
- **VPC-8 — lateral movement, network segmentation, and IPv6
  controls (8 controls, 3 chains). Final VPC batch.** Closes
  the category-14 (lateral movement) and category-12 (IPv6)
  clusters; completes the eight-batch VPC gap-closure
  programme.
  Segmentation (5): `SEGMENT.ENVMIX` (production and non-
  production share network path, high), `SEGMENT.TIERING`
  (web/app/data tiers in same subnet, medium), `SEGMENT.BASTION`
  (bastion has unrestricted internal egress, high),
  `SEGMENT.EASTWEST` (TGW inter-VPC traffic uninspected, medium),
  `SEGMENT.LAMBDA` (VPC-attached Lambda has unrestricted SG
  egress, medium).
  IPv6 (3): `IPV6.EGRESSONLY` (IPv6 VPC without egress-only IGW
  — bidirectional internet exposure since IPv6 has no NAT,
  high), `IPV6.ROUTE.PUBLIC` (subnet private on IPv4 but public
  on IPv6 — the most deceptive IPv6 misconfiguration, high),
  `IPV6.NACL` (NACL IPv6 rules don't match IPv4 restrictions —
  the parity gap at the NACL layer, medium).
  Chains: `vpc_lateral_movement` (envmix + bastion or eastwest),
  `vpc_ipv6_shadow_exposure` (no EIGW + ROUTE.PUBLIC or SG IPv6
  parity gap), `vpc_segmentation_failure` (no tiering + default
  NACL or default SG in use).
  18 e2e fixtures (16 base + two worst-case variants:
  envmix-tgw with cross-VPC environment mixing via TGW, and
  ipv6-route-public-natigw with NAT for IPv4 but IGW for IPv6).
  8 triage overrides. Docs and README regenerated (1386 controls).
- **refactor: extract capability vocabulary from core engine.**
  Moved `ValidCapabilities` from `internal/core/controldef/` to
  `internal/builtin/capabilities/`. Core now defines the
  `CapabilityRegistry` contract; the catalog layer provides the
  data. After this change, no domain expansion (AWS, M365,
  Cloudflare, EKS, GCP, Azure, or any future domain) requires
  modifying `internal/core/`. 108 domain-expansion commits, zero
  core changes — that pattern now extends to any new
  attack-path capability strings as well. `Validate()` is now
  structural-only; vocabulary is checked via the new
  `ValidateCapabilities(registry)` method. 12 production
  callers updated to thread the registry through; tests use
  locally-declared registries instead of the previously-global
  vocabulary.
- **VPC-7 — load balancer ghost references, DNS firewall, and
  Network ACL controls (9 controls, 3 chains).** Combines three
  smaller gap clusters from categories 2 (NACLs), 8 (DNS), and
  9 (ELB). ELB ghost family: `TARGET.GHOST` (deregistered or
  terminated targets remain registered, medium), `LISTENER.GHOST`
  (listener rule forwards to a deleted target group — silent
  502/503, high), `CERT.GHOST` (expired or deleted ACM cert on
  HTTPS listener — public TLS failure, high), `SG.GHOST` (LB
  references a deleted security group — inconsistent firewall
  state, high). DNS firewall: `DNSFIREWALL.ENABLED` (no Route53
  Resolver DNS Firewall rule group on VPC, medium),
  `DNSFIREWALL.MANAGEDLISTS` (DNS Firewall present but no AWS
  managed threat-intel lists, medium). NACL: `DEFAULT.INUSE`
  (subnet uses default allow-all NACL — no subnet-level
  defense-in-depth, medium), `RULE.ORDER` (deny rules ordered
  after matching allow rules — never evaluate, medium),
  `UNRESTRICTED` (custom NACL allows all traffic — defense-in-
  depth theater, medium). Chains: `elb_ghost_cascade`
  (multiple LB ghost references — systematic decommissioning
  failure), `vpc_dns_exfiltration` (no DNS firewall + unrestricted
  DNS egress or no flow logs), `vpc_nacl_false_confidence`
  (ineffective deny rules OR allow-all custom NACL — appears
  filtered, isn't). 20 e2e fixtures (18 base + 2 worst-case
  variants: target-ghost-total with every target a ghost and
  cert-ghost-deleted distinguished from merely expired).
  9 triage overrides. Docs and README regenerated (1378 controls).
- **VPC-6 — flow log deepening and VPC endpoint coverage (9 controls,
  3 chains).** Closes the category-7 flow-log cluster and the
  category-6 endpoint cluster. Prompt spec asked for 10 controls;
  `MISSING.S3` was a duplicate of the existing
  `CTL.VPC.ENDPOINT.S3.001`, so shipped 9. Flow-log additions:
  `SUBNET` (sensitive subnet with no coverage at either subnet or
  VPC scope, medium), `STATUS` (flow log configured but not ACTIVE —
  the "everything appears to work" pattern, high), `FORMAT` (default
  format omits pkt-srcaddr/tcp-flags/etc. needed for forensics,
  medium), `DESTINATION.SECURE` (public/unencrypted/deletable/low-
  retention destination, high, OR predicate across four dimensions),
  `BIDIRECTIONAL` (TrafficType is ACCEPT or REJECT only — half the
  record missing, medium). Endpoint additions:
  `MISSING.CRITICAL` (missing interface endpoint for one or more of
  KMS/Secrets Manager/STS/SSM/CloudWatch Logs/ECR, medium),
  `SG.BROAD` (endpoint SG permits full VPC CIDR rather than specific
  workload SGs, medium), `DNS` (Private DNS disabled — endpoint
  bypassed because standard service DNS routes to public IP, low).
  Chains: `vpc_flow_visibility_gap` (flow logs not active + partial
  capture or insecure destination), `vpc_endpoint_bypass` (no
  Private DNS + broad SG or anonymous policy), `vpc_private_subnet_leakage`
  (missing S3 gateway or critical interface endpoints + unrestricted
  egress). 18 e2e fixtures (16 base + 2 worst-case variants:
  status-deliver-error with ACTIVE status but ERROR delivery, and
  endpoint-many-missing with all six critical endpoints absent).
  8 triage overrides. Docs and README regenerated (1369 controls).
- **VPC-5 — AWS Network Firewall deepening (5 controls, 3 chains).**
  Closes the Network Firewall gap cluster in category 10. Prompt
  spec asked for 8 controls; three turned out to duplicate existing
  ones (`CTL.VPC.NETWORK.FIREWALL.001` covered ENABLED,
  `CTL.NETFIREWALL.MULTIAZ.001` covered SINGLEAZ, `CTL.NETFIREWALL.LOG.001`
  covered LOGGING), so shipped 5 distinct additions. New controls:
  `ROUTING` (firewall deployed but route tables bypass it — the
  "smoke detector not connected to power" pattern, critical),
  `RULES.STATEFUL` (no stateful rule groups — packet filter, not
  connection-aware firewall, high), `RULES.PERMISSIVE` (allow-any
  rule inside a rule group short-circuits inspection, high),
  `MODE` (stateful default is ALERT — detection without
  prevention, high), `TLS` (no TLS inspection — HTTPS content
  bypass, medium). Chains: `netfirewall_ineffective`
  (routing-bypass + alert-mode or no-logging — security theater),
  `netfirewall_content_blind` (no TLS + no stateful = blind to
  both content and context), `vpc_no_inspection` (no firewall +
  no flow logs or unrestricted egress). 12 e2e fixtures (10 base
  + two worst-case variants: routing-silent with configured-looking
  rules, mode-suricata with 1247 stateful rules still in alert).
  5 triage overrides. Docs and README regenerated (1361 controls).
- **VPC-4 — internet connectivity and subnet architecture controls
  (10 controls, 3 chains).** Closes the category-4 internet-connectivity
  gaps and subnet-architecture gaps from category 3. Covers the
  "public-by-default" failure mode (main route table with IGW route +
  subnet `MapPublicIpOnLaunch`) and the database-in-public-subnet
  pattern. New controls: `IGW.UNNECESSARY` (latent IGW attachment,
  medium), `NAT.SINGLEAZ` (single-AZ egress bottleneck, medium),
  `NAT.LOGGING` (egress choke-point unlogged, medium), `EIP.ORPHANED`
  (unassociated Elastic IP, low), `EIP.EXCESSIVE` (multiple EIPs on
  one instance, medium), `SUBNET.AUTOPUBLIC` (`MapPublicIpOnLaunch`
  subnet default, high), `SUBNET.PRIVATEDB` (database subnet has IGW
  route, high), `ROUTETABLE.MAIN.PUBLIC` (main route table has IGW
  route, high), `ROUTETABLE.ORPHANED` (unassociated route table,
  low), `DEFAULT.RESOURCES` (workloads in default VPC, high). Chains:
  `vpc_default_exposure` (resources in default VPC + auto-public-IP
  or default SG in use), `vpc_public_by_default` (main-RT IGW route +
  subnet auto-public), `vpc_database_exposure` (database in public
  subnet OR `CTL.RDS.PUBLIC.001`). 20 e2e fixtures, 10 triage
  overrides, docs and README regenerated (1356 controls).
- **VPC-3 — VPN, Client VPN, and Direct Connect controls (8 controls, 3
  chains).** Closes the hybrid-connectivity gap cluster in the VPC
  taxonomy. Site-to-site VPN: `ENCRYPTION.WEAK` (sub-AES-256 cipher
  suites, high), `TUNNEL.DOWN` (redundancy loss or connectivity outage,
  high), `PSK` (shared-secret peer authentication, medium), `LOGGING`
  (tunnel event log disabled, medium). Client VPN: `AUTH` (all-traffic
  allow with no authorization rules, high), `LOGGING` (connection log
  disabled, high), `SPLITTUNNEL` (client bridges VPC and internet,
  medium). Direct Connect: `ENCRYPTION` (no VPN overlay and no MACsec,
  high). Chains: `vpc_vpn_compromise` (weak cipher + no log or PSK),
  `vpc_clientvpn_exposure` (all-traffic + no log or split tunnel),
  `vpc_hybrid_unencrypted` (any unencrypted hybrid path). 18 e2e
  fixtures, 8 triage overrides, docs and README regenerated
  (1346 controls).
- **VPC-2 — peering and Transit Gateway controls (9 controls, 3 chains).**
  Closes the largest remaining cluster in the VPC taxonomy: cross-VPC
  connectivity. Peering coverage adds `CROSSACCOUNT` (peer outside the
  organization, high), `BIDIRECTIONAL` (return routes not required by the
  use case, medium), `PENDING` (stale pending-acceptance request, medium),
  and `DNS` (resolution disabled, low). Transit Gateway coverage adds
  `ROUTING.ALLTOALL` (segmentation collapse, high), `FLOWLOGS` (central
  hub unlogged, high), `PROPAGATION` (VPN/DX route injection risk,
  medium), `BLACKHOLE` (silent traffic loss, medium), and
  `ATTACHMENT.ISOLATED` (isolated VPC attached to a shared hub, medium).
  Chains: `vpc_peering_exposure` (cross-account peer + broad routing),
  `vpc_tgw_segmentation_failure` (all-to-all + unlogged or isolated
  attachment), `vpc_transit_ghost` (blackhole routes + endpoint ghost
  refs). Skipped `PEERING.ROUTING.BROAD` — duplicates the existing
  `CTL.VPC.PEERING.ROUTES.001` (same field, same check). 18 e2e fixtures,
  9 triage overrides, docs and README regenerated (1337 controls).
- **DELTA section on findings.** Mechanically derived fix paths computed
  from the predicate and observed values. Each DeltaPath shows the
  property label (from registry), current observed value, and the fix
  action (operator inversion). For AND predicates, independent fix paths
  shown with "any ONE eliminates this finding" header. Uses the same
  property registry as defect derivation. Coverage: 672/675 controls.
  Counterfactual verified: applying the delta's suggested change
  eliminates the finding. Renders in both text and JSON output.
- **Predicate-derived defect descriptions.** Controls without per-control
  defect overrides now get mechanically generated DEFECT text from their
  predicate tree. A property-path registry maps observation fields to
  domain-meaningful labels (150+ overrides, algorithmic fallback for the
  rest). Combined with operator-phrase mapping, the derivation produces
  accurate sentences like "EBS volume encryption is not enabled" or
  "S3 BlockPublicAcls setting is not enabled." Coverage: 672 of 675
  controls (99.6%) now have defect descriptions — 121 from per-control
  overrides, 551 from derivation, 3 not derivable (complex predicates).
  Per-control overrides still take precedence. Derivation runs in shared
  core, used by both CLI and library.
- **Family template inheritance verified end-to-end.** Targeted test
  (`TestApply_FamilyTemplateInheritance`) confirms 42 of 54 findings
  inherit family-level infection/failure from the builtin catalog, 12
  retain per-control overrides. Inheritance works through the embedded
  `_triage/` tree loaded by the builtin ControlStore. File-based loader
  applies triage when `_triage/` exists in the controls directory;
  self-contained fixtures without `_triage/` fall back to inline fields
  (backward compatible).
- **Triage separation: `_triage/` directory with family templates and
  per-control overrides.** Security definitions (predicate,
  classification, severity) and troubleshooting context (defect,
  infection, failure) now live in separate files. 121 per-control
  overrides extracted from control YAMLs into
  `controls/_triage/overrides/`. 47 family-level templates authored
  in `controls/_triage/families/`, providing infection/failure prose
  for every control family. Engine joins both trees at runtime with
  per-field inheritance: override > family template > empty. Coverage:
  121 controls have full per-control triage (override); remaining
  554 inherit family-level infection/failure. The `_triage/` directory
  is `_`-prefixed so the control scanner skips it during YAML
  discovery.
- **Defect/infection/failure metadata on 40 IAM controls** —
  CRED (7), TRUST (6), ROLE (6), IDENTITY (6), ROOT (5), SCP (4),
  PASSWORD (4), ZT (2) sub-families authored. Covers credential
  lifecycle (rotation, expiry, dormancy, recurrence), trust policy
  hardening (confused deputy, OIDC scoping, source-ARN conditions,
  external ID), role hygiene (category mixing, intent tags, permission
  drift, break-glass TTL), blast radius analysis (resource threshold,
  cross-account, chain depth, sensitive resource concentration), root
  account hardening (MFA, access keys, usage), SCP guardrails
  (dangerous allows, OU coverage, identity creation), password policy,
  and zero trust principles. 0 flagged as ambiguous. 1 golden updated
  (e2e-hipaa-cross-domain, additive only — ROOT controls). Total
  authored: 121 of 675 controls (17.9%). Remaining IAM: 20 controls
  across smaller sub-families. Next batch: complete remaining IAM
  (20 controls) then pivot to K8S (64 controls).
- **Defect/infection/failure metadata on 38 IAM controls** —
  IAM.ESCALATE (22) and IAM.POLICY (16) sub-families authored. Covers
  all Rhino Security Labs privilege-escalation techniques (PassRole
  chains, self-modification, credential manipulation, trust policy
  rewriting, group-hop escalation), plus policy hygiene controls
  (admin wildcard, NotAction shadow logic, separation of duties,
  ghost references, inline policies, MFA enforcement). 0 controls
  flagged as ambiguous. 0 goldens updated (IAM controls not exercised
  by existing fixtures). Total authored: 81 of 675 controls (12.0%).
  Next batch: remaining IAM sub-families (62 controls) or pivot
  to K8S (64 controls).
- **Defect/infection/failure metadata on all 29 CTL.EC2 controls** —
  complete EC2 family authored in one batch. Each control now carries
  `defect`, `infection`, and `failure` prose enabling adopters to triage
  findings without external reference. Covers: encryption (EBS volumes,
  snapshots, Nitro Enclaves), network exposure (public IPs, IMDSv2,
  security groups, VPC endpoints, subnets, default VPC), identity
  (instance profiles, IAM roles, user-data credentials), audit (detailed
  monitoring, SSM session logging), governance (launch templates, SSM
  management), resilience (ASG health checks, termination protection),
  and version currency (AMI age). Total authored: 43 of 675 controls
  (14 S3 + IAM + Lambda prior + 29 EC2 this batch). No case
  programs affected (none exercise EC2 controls). 1 golden file updated
  (e2e-hipaa-cross-domain, additive only). Next batch: IAM
  sub-families (ESCALATE + POLICY, ~38 controls).
- **Three per-service IAM privilege-escalation controls** grounded in
  three disclosed incidents. Each detects a distinct privesc path
  where a principal can invoke a service whose role exceeds the
  principal's effective permissions. Per-service framing was chosen
  over a generalized predicate so service-specific preconditions
  (`CAPABILITY_IAM` for CloudFormation, source-repo write for
  CodeBuild) can gate the finding and suppress the CI/CD-pipeline
  false-positive class.
  - `CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001` — `iam:PassRole`
    plus `cloudformation:CreateStack` without a `CAPABILITY_IAM`
    denial. Grounded in the Yani disclosure (Sep 2022).
    CCM: `CCC-04`, `IAM-05`, `IAM-16`.
  - `CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001` — `iam:PassRole`
    plus `ec2:RunInstances` on an instance-profile role whose
    permissions exceed the principal's. Grounded in the Security
    Shenanigans disclosure (Oct 2020). CCM: `IAM-05`, `IAM-16`.
  - `CTL.IAM.ESCALATE.STARTBUILD.001` — `codebuild:StartBuild`
    plus source-repo write on a project whose service role exceeds
    the principal's. Non-PassRole variant. Grounded in the HTB
    Business CTF disclosure (Jun 2025). CCM: `AIS-06`, `IAM-05`,
    `IAM-16`.
  Observation contract (consumed by the controls) extends
  `identity.escalation` with per-vector objects: `passrole_createstack`,
  `passrole_runinstances`, `startbuild_source_write`. Each carries
  `present`, `target_role`, `permission_delta`, and vector-specific
  fields (`via_capability_iam`, `target_project`, `source_type`).
  Extractor work to populate these fields lives outside this repo;
  fixtures carry the shape hand-authored.
- **CCM v4 mapping metadata on controls** — optional `compliance.ccm_v4`
  list on `ctrl.v1` accepting CSA CCM v4 control IDs in `DOMAIN-NN`
  form (e.g., `IAM-05`, `CCC-07`). Absence = not yet mapped; empty list
  = no CCM mapping applicable. 630 / 630 built-in controls back-filled
  via directory + function inference (100% coverage). Reference at
  `docs/reference/ccm-v4-controls.md`.
- **CCM v4 mappings propagate to evaluation findings** — additive
  `control_compliance_ccm_v4` field on each finding in `out.v0.1`
  output; no change to the existing `control_compliance` map or any
  other framework mappings (SOC 2, PCI, NIST, FedRAMP, ISO, HIPAA, CIS).
- **CCM v4 mappings carried in OCSF export** — populated into the
  OCSF 1.1 `compliance.requirements` array as `CCM:<ID>` strings so
  downstream SIEMs can filter by framework prefix. No change to other
  OCSF fields. Wire-format `schema_version` stays at `out.v0.1` since
  the change is additive under the 0.1.x contract.
- `stave config delete <key>` — remove a project config key, reverting to default
- Severity levels populated on all 43 S3 controls (10 critical, 20 high, 11 medium, 2 low)
- Compliance metadata (`compliance` field) on control definitions — maps framework names to control IDs
- Compliance mappings on 8 key controls (CIS AWS v1.4.0, PCI DSS v3.2.1, SOC 2)
- `--min-severity` flag on `apply` — filter controls by minimum severity level
- `--control-id` flag on `apply` — run a single specific control
- `--exclude-control-id` flag on `apply` — exclude specific controls (repeatable)
- `--compliance` flag on `apply` — run only controls with a mapping for the given framework
- `stave report` severity breakdown section (findings by severity table)
- `stave report` compliance summary section (framework → findings count + controls)
- SEVERITY column in report TSV output
- `control_severity` and `control_compliance` fields in evaluation findings output

### Changed
- **Breaking:** Removed `--out` flag from `apply`, `check`, `verify`, `ci diff`,
  `ci baseline check`, `report`, `ci gate`, `snapshot diff`, `snapshot upcoming`,
  and `snapshot status`/`snapshot risk` (formerly `snapshot hygiene`). Use shell redirection (`> file`) instead. Commands that
  create files (`generate`, `ingest`, `ci baseline save`, `enforce`, `ci fix-loop`)
  keep `--out` unchanged.
- **Breaking:** Removed `--summary-out` flag from `snapshot upcoming`. Pipe output
  to capture: `stave snapshot upcoming > "$GITHUB_STEP_SUMMARY"`.
- **Breaking:** Removed `-O` shorthand from `ci gate`.
- **Breaking:** Removed `-o` shorthand from `--out` flag on enforce, fix-loop, verify,
  ci diff, generate, report, baseline, and ingest. `-o` now consistently means
  `--observations` across all commands.
- **Breaking:** Removed `-i` shorthand from `--input` on ingest. `-i` now consistently
  means `--controls`.
- **Breaking:** Removed `-s` shorthand from `--step` on template. `-s` now consistently
  means `--sort`.
- `stave report --format json` now includes `findings_by_severity` and `compliance_summary` aggregations
- S3 extractor functions now accept `context.Context` for cancellation support,
  consistent with observation and control loaders
- Enabled `goimports` formatter in golangci-lint configuration

## [0.0.1] - 2026-02-17

### Added
- Core evaluation engine with duration tracking and recurrence detection
- 40 S3 controls covering public exposure, ACL, encryption, versioning, access logging, lifecycle, object lock, tenant isolation, and write scope
- CLI commands: validate, apply, diagnose, ingest --profile aws-s3, apply --profile aws-s3, verify, enforce, report, counterfactual, capabilities, alias, trace
- `--template` flag on apply, diagnose, and validate for custom output formatting
- Command alias system (`stave alias set|list|delete`) with user config storage
- JSON and text output formats
- Observation schema (obs.v0.1) and control DSL (ctrl.v1)
- Terraform plan extraction for S3 assets
- Golden-file E2E test framework with 95+ test cases
- OpenSSF Scorecard, signed releases, SLSA provenance, SBOM

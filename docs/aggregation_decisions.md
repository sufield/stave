# Aggregation Ownership: Librarian vs Judge

## Purpose

This document is the contract that drives Iteration 1 SIR design and
Iteration 4 differential gating. For every compound check that
combines two or more security vectors into a single verdict, it
records WHICH ENGINE owns the aggregation:

- **Librarian (Stave)** — Stave aggregates the vectors and exposes the
  effective state in the SIR. The Z3 solver reasons over the already-
  combined fact.
- **Judge (Solver)** — Stave exposes raw vectors in the SIR. The Z3
  solver applies the combination rules itself.

**Default rule.** Aggregation per AWS service is *data work*: it
depends on AWS evaluation semantics (implicit deny, explicit-deny
precedence, BPA short-circuit, ACL ownership rules, SCP intersection,
boundary intersection). Data work belongs to the Librarian. The Judge
gets to reason about *logic* (predicate satisfaction, witness search,
counterexample generation) over already-aggregated effective sets.

**Exception.** If a compound's combination rule is already declarative
(a Z3-friendly predicate over disjoint primitive facts with no
service-specific quirks), push it to the Judge.

## How to read each row

Each row covers one compound check. Fields:

- **Check** — the control / aggregation site.
- **Vectors** — the inputs being combined.
- **Operator** — how they combine (∩, ∪, override, layered veto).
- **Resource type** — what the aggregate applies to.
- **Currently typed** — does the existing code return a struct or a
  bare bool deep in a function body?
- **Owner** — Librarian or Judge.
- **Rationale** — why.
- **SIR exposure** — what the SIR contract emits to support this
  decision.

---

## AWS S3

### S3.1 — Block Public Access (BPA) bucket-level vs account-level

| Field | Value |
|---|---|
| Check | `accessBlockPublic` (`ACCESS.001`) at `internal/platform/providers/aws/compliance/access_block_public.go:34` |
| Vectors | bucket-level BPA (4 flags) + account-level BPA |
| Operator | layered veto with severity downgrade: account-BPA fully blocked AND bucket-BPA absent → severity Low; otherwise Critical |
| Resource type | S3 bucket |
| Currently typed | yes — `S3Controls.IsPublicAccessFullyBlocked()` and `S3Controls.AccountPublicAccessFullyBlocked` |
| **Owner** | **Librarian** |
| Rationale | Pure AWS-semantics aggregation. The Z3 solver should not have to know that account-BPA acts as a fallback ceiling for bucket-BPA gaps. |
| SIR exposure | `EffectivePermissionFact` carries the post-BPA effective access set. The raw four BPA flags + account-BPA flag still flow through `AssetFact.Properties` so a future solver wanting to redo the aggregation can. |

### S3.2 — Effective public exposure (Bucket Policy ∩ ACL ∩ BPA ∩ Ownership)

| Field | Value |
|---|---|
| Check | distributed across `policy.Document.Assess`, `acl.Assess`, `S3Controls.IsPublicAccessFullyBlocked`, `S3Properties.ACLsDisabled` |
| Vectors | resource-based bucket policy + ACL grants + Public Access Block + Object Ownership setting |
| Operator | `ACLsDisabled (BucketOwnerEnforced) ⇒ ACL ignored`; then `BPA(BlockPublicACLs|IgnorePublicACLs|BlockPublicPolicy|RestrictPublicBuckets) shorts the corresponding source`; remaining policy ∪ ACL grants intersect with implicit-deny semantics |
| Resource type | S3 bucket |
| Currently typed | partially — `policy.Assessment` and `acl.Assessment` are typed; the cross-source aggregation lives ad-hoc across multiple control evaluators |
| **Owner** | **Librarian** |
| Rationale | This is the single largest source of mis-modeling risk. AWS semantics here are well-defined but tricky (BPA short-circuits ACL evaluation, BucketOwnerEnforced disables ACL grants entirely, policy and ACL grants merge by union but BPA can suppress either). Putting this in the solver means the solver has to encode AWS evaluation order — exactly the kind of operational coupling Iteration 1 is meant to eliminate. |
| SIR exposure | `EffectivePermissionFact` per (bucket, principal/scope) pair, with `ContributingSources` pointing at every policy statement, ACL grant, and BPA flag that survived the aggregation. A solver wanting to model AWS evaluation directly can read `AssetFact.Properties` for the raw vectors, but the canonical answer the SIR commits to is the Librarian's. |

### S3.3 — Network-scope merge across statements (weakest-wins)

| Field | Value |
|---|---|
| Check | `analysisState.updateWeakestScope` in `s3/policy/analyzer.go:175` |
| Vectors | per-statement `NetworkScope` (VPC condition, IP condition, no condition) |
| Operator | weakest-wins merge across all statements: a single statement without a network condition opens the bucket to the public internet regardless of how restrictive every other statement is |
| Resource type | bucket policy |
| Currently typed | yes — `kernel.NetworkScope` is a typed enum |
| **Owner** | **Librarian** |
| Rationale | AWS evaluation semantics. Weakest-wins is a domain rule about how multiple Allow statements compose. The solver shouldn't need to know it. |
| SIR exposure | `EffectivePermissionFact.AllowedFromNetwork` carries the post-merge set of network scopes that effectively permit access. Per-statement scopes still appear in `RuleFact` form for traceability. |

### S3.4 — Network restriction predicate (`HasVPCCondition ∨ HasIPCondition`)

| Field | Value |
|---|---|
| Check | `S3Access.IsNetworkRestricted` consumed by `accessNetworkRestriction` (`ACCESS.003`) |
| Vectors | `HasVPCCondition`, `HasIPCondition` |
| Operator | logical OR |
| Resource type | S3 bucket |
| Currently typed | yes — `S3Access` struct |
| **Owner** | **Judge** |
| Rationale | Trivial declarative OR over two disjoint primitive booleans. Z3-friendly. No AWS-specific aggregation rule. The Judge handles this directly to demonstrate the seam works for the simplest possible compound. |
| SIR exposure | The two booleans appear as separate `RuleFact` entries on the `ControlFact`'s `Predicate`; the solver evaluates `Or(has_vpc_condition, has_ip_condition)` directly. |

### S3.5 — Presigned URL restriction (`HasSignatureAgeGuardrail ∨ HasAuthTypeGuardrail`)

| Field | Value |
|---|---|
| Check | `PolicyStatement.RestrictsPresignedURLAccess` consumed by `accessPresignedURL` (`ACCESS.009`) |
| Vectors | `HasSignatureAgeGuardrail`, `HasAuthTypeGuardrail` |
| Operator | logical OR |
| Resource type | bucket policy statement |
| Currently typed | yes — methods on `PolicyStatement` |
| **Owner** | **Judge** |
| Rationale | Same shape as S3.4: declarative OR over two boolean predicates. No AWS-specific evaluation rule. The Judge sees the per-statement booleans and evaluates them. |
| SIR exposure | Per-statement `ConditionFact` entries naming `s3:signatureAge` and `s3:authType` operators; the solver computes the OR. |

### S3.6 — Public ListBucket compound (`IsAllow ∧ HasWildcardPrincipal ∧ HasAction("s3:ListBucket")`)

| Field | Value |
|---|---|
| Check | `PolicyStatement.IsPublicListGrant` consumed by `accessPublicList` (`ACCESS.011`) |
| Vectors | three predicates per statement |
| Operator | logical AND |
| Resource type | bucket policy statement |
| Currently typed | yes — methods on `PolicyStatement` |
| **Owner** | **Judge** |
| Rationale | Pure declarative conjunction over disjoint typed predicates. The historical reason this fired late (after S3.2's effective-access aggregation) is that the *answer* depends on the effective access set; but the *predicate itself* is solver-friendly once given the per-statement primitives. The solver gets the per-statement facts and the post-aggregation effective set; it composes them. |
| SIR exposure | Per-statement booleans (`IsAllow`, `HasWildcardPrincipal`, `HasAction(s3:ListBucket)`) plus the corresponding `EffectivePermissionFact` so the solver can compose. |

### S3.7 — Encryption mode compound (`IsEnabled ∧ IsKMS ∧ ¬IsAWSManagedKey ∧ KMSMasterKeyID != ""`)

| Field | Value |
|---|---|
| Check | `controlsKmsCmk` (`CONTROLS.001.STRICT`) at `internal/platform/providers/aws/compliance/controls_kms_cmk.go:35` |
| Vectors | four predicates on `S3Encryption` |
| Operator | logical AND with explicit Fail-fast ordering (different remediation per failing predicate) |
| Resource type | S3 bucket |
| Currently typed | yes — `S3Encryption` struct + methods |
| **Owner** | **Judge** |
| Rationale | Declarative conjunction. The fail-fast diagnostic ordering is presentation, not aggregation. The solver evaluates the AND and the Librarian renders the per-predicate diagnostic (we already have the failing-predicate from the Z3 model). |
| SIR exposure | `S3Encryption` fields appear under `AssetFact.Properties` as separate `RuleFact` entries. |

---

## AWS IAM

### IAM.1 — Effective principal permissions (Identity ∩ SCP ∩ Boundary − Deny)

| Field | Value |
|---|---|
| Check | `iam.Resolve` at `internal/platform/providers/aws/iam/resolve.go:81` |
| Vectors | identity-based policies (managed + inline + group), SCP hierarchy, permission boundary, explicit denies (across all layers) |
| Operator | `effective = (identity ∩ scp_ceiling ∩ boundary_ceiling) − explicit_denies`; SCP hierarchy itself uses intersection across the org tree, not union (a privilege-escalation hazard if reversed) |
| Resource type | IAM principal (user / role / group) |
| Currently typed | yes — `ResolutionInput`, `ResolvedPermissions`, `ActionGrant` |
| **Owner** | **Librarian** |
| Rationale | The single most service-specific aggregation in the codebase. AWS evaluation semantics here are subtle: SCP intersection (not union), explicit-deny precedence, boundary as a separate ceiling, "incomplete" handling for missing SCP/boundary documents in the snapshot. Modeling this in Z3 means re-implementing AWS's IAM evaluation engine — the exact infrastructure-specific work the Librarian was meant to absorb. |
| SIR exposure | `IdentityFact.Validity[].Permissions` carries the post-aggregation `EffectiveAllow` set per principal per validity window. SCP intersection result, boundary effectiveness flag, and the original layer-by-layer grants flow through `IdentityFact.Properties` for solver introspection but are NOT the canonical answer. |

### IAM.2 — Privilege classification ladder (admin / elevated / standard / limited / none)

| Field | Value |
|---|---|
| Check | `classifyPrivilege` at `iam/resolve.go:381` |
| Vectors | post-resolution effective grants + `isEffectivelyBroadResource` per grant + admin-action whitelist + service-count threshold |
| Operator | layered classification: `hasAdmin > hasElevated > serviceCount > 2 > else limited / none` |
| Resource type | IAM principal |
| Currently typed | yes — `PrivilegeLevel` enum |
| **Owner** | **Librarian** |
| Rationale | The decision rules ("`iam:*` ⇒ admin", "`s3:*` on `*` ⇒ elevated", "more than 2 services ⇒ standard") encode AWS-semantics policy not logical reasoning. Z3 over arbitrary action ladders adds no value. |
| SIR exposure | `IdentityFact.Validity[].Properties["privilege_level"]` carries the classification. Raw effective grants still appear under `Permissions` for solvers that want to redo classification. |

### IAM.3 — Resource-based policy access index merge

| Field | Value |
|---|---|
| Check | `iam.AddResourcePolicy` at `iam/resource_access.go:35` (extracts), then merged into `ResolvedPermissions.ResourcePolicyGrants` |
| Vectors | per-resource policy statements ∪ per-principal identity policies (cross-account / public detection requires both) |
| Operator | union of grants, with cross-account / public flags computed at merge time |
| Resource type | IAM principal × AWS resource |
| Currently typed | yes — `ResourceAccessEntry`, `ResourcePolicyGrant` |
| **Owner** | **Librarian** |
| Rationale | "What can this principal reach via resource-based policies on other accounts' resources" is a question that requires Stave's full snapshot. The solver can't reconstruct it without re-implementing the resource-policy parser. |
| SIR exposure | Cross-account `EffectivePermissionFact` entries with `ContributingSources` naming both the resource policy statement and the identity grant that combined to create access. |

### IAM.4 — Transitive role chains (`sts:AssumeRole` traversal up to `MaxChainDepth`)

| Field | Value |
|---|---|
| Check | `iam.ResolveChains` at `iam/role_chain.go:59` |
| Vectors | per-principal `sts:AssumeRole` grants + per-role trust policies + per-role resolved permissions + cycle detection + depth cap |
| Operator | bounded transitive closure with cycle detection; final-role permissions become the principal's "transitive admin" set |
| Resource type | IAM principal |
| Currently typed | yes — `RoleChain`, `RoleHop`, `ChainTerminationReason` |
| **Owner** | **Librarian** |
| Rationale | Graph-traversal with AWS-specific termination conditions (5-hop cap, cycle detection, missing-role-in-snapshot handling). The traversal itself isn't AWS-specific but the inputs it consumes (resolved permissions per role, trust policies) come from IAM.1, which is Librarian-owned. Pushing the chain to the solver means pushing IAM.1 too. |
| SIR exposure | `IdentityFact.Validity[].Properties["role_chains"]` carries the resolved chains. Each chain's final-role permissions appear in the principal's effective permissions set. |

---

## AWS KMS

### KMS.1 — Customer-managed key vs AWS-managed key classification

| Field | Value |
|---|---|
| Check | `S3Encryption.IsAWSManagedKey` at `compliance/prop_helper.go:88` |
| Vectors | KMS key ID string match against `alias/aws/s3` |
| Operator | string comparison (lowercase, exact or suffix match against `/alias/aws/s3`) |
| Resource type | S3 bucket's encryption configuration |
| Currently typed | yes — method on `S3Encryption` |
| **Owner** | **Judge** |
| Rationale | Pure string predicate, declarative, Z3-friendly. The aggregation lives entirely in S3.7's compound; there's no separate KMS aggregation worth a Librarian seat. |
| SIR exposure | The KMS key ID flows through as a primitive string field; the solver applies the predicate. |

### KMS.2 — Key isolation across resources (`KeyUsageIndex`)

| Field | Value |
|---|---|
| Check | `engine.buildKeyUsageIndexForSnapshot` and `EnrichKeyIsolation` in `internal/core/evaluation/engine/key_isolation.go` |
| Vectors | every asset's `cryptography.kms_key_id` + every asset's `tags.data-classification` |
| Operator | snapshot-wide index: per-key-ID, build the set of distinct sensitivity levels using that key. Asset is non-isolated if its key is shared across multiple sensitivity levels. |
| Resource type | KMS key (cross-resource property) |
| Currently typed | yes — `KeyUsageIndex`, `KeyUsageEntry` |
| **Owner** | **Librarian** |
| Rationale | Snapshot-wide aggregation. The "did this key carry data of multiple sensitivity levels" question requires walking every asset in the snapshot. Z3 over arbitrary cross-resource indices adds no value; the index IS the aggregation. |
| SIR exposure | Each asset's `Properties["cryptography"]["key_isolation"]` carries the post-aggregation `is_exclusive_to_domain`, `domain_count`, `mixed_classification` flags. The full `KeyUsageIndex` does not need to appear in the SIR — its consumers consume the per-asset post-enrichment. |

---

## Cross-Domain (engine-level)

### ENG.1 — Compound chain detection (`risk.DetectChains`)

| Field | Value |
|---|---|
| Check | `risk.DetectChains` at `internal/core/evaluation/risk/chain_engine.go:52` |
| Vectors | per-asset failing-control set + chain definition's `ControlIDs` + chain `EscalationThreshold` |
| Operator | per (chain × asset): `len(failing ∩ chain.ControlIDs) >= chain.EscalationThreshold ⇒ chain fires` |
| Resource type | asset (chain attaches to the asset) |
| Currently typed | yes — `CompoundFinding`, `FailingControl`, `ChainDefinition` |
| **Owner** | **Judge** |
| Rationale | Declarative threshold predicate over a per-asset set. Z3-friendly. The chain catalog itself is data the solver consumes; chain firing is logic the solver evaluates. |
| SIR exposure | `Document.Controls[i].Properties["chain"]` carries the `ChainDefinition` shape; per-asset failing-control sets fall out of the `EffectivePermissionFact` + `ControlFact` joint query. |

### ENG.2 — Attack-stage summary (`risk.BuildAttackStageSummary`)

| Field | Value |
|---|---|
| Check | `risk.BuildAttackStageSummary` |
| Vectors | per-control `AttackStage` annotation + per-asset failing controls |
| Operator | per attack stage, max severity across all controls in the stage that are failing for any asset |
| Resource type | snapshot-wide |
| Currently typed | yes — `AttackStageSummary` |
| **Owner** | **Librarian** |
| Rationale | Snapshot-wide aggregation. The summary is a presentation-layer roll-up of per-control facts; the solver should not need to know the kill-chain ordering or per-stage worst-severity rule. |
| SIR exposure | The summary itself does not need to live in the SIR — the solver produces findings, the Librarian rolls them into `AttackStageSummary` for the report. |

### ENG.3 — Exposure ranking (`risk.RankExposures`)

| Field | Value |
|---|---|
| Check | `risk.RankExposures` |
| Vectors | finding base score + chain bonus + duration factor + blind multiplier + blast multiplier |
| Operator | multiplicative composition, sorted descending |
| Resource type | per finding |
| Currently typed | yes — `RankInput`, `ExposureRank`, `ScoreBreakdown` |
| **Owner** | **Librarian** |
| Rationale | Scoring is a presentation/policy concern, not a logical-reasoning concern. The solver returns findings; ranking is the report-builder's job. |
| SIR exposure | None — ranking is a post-solver phase that operates on the findings the solver returned. |

---

## Decisions for Iteration 1.2 (SIR design)

The SIR contract from Prompt 1.2 must include:

- **`EffectivePermissionFact` with `ContributingSources []SourceRef`** —
  the canonical post-aggregation effective access set per (resource,
  principal) pair, sourced from S3.1, S3.2, S3.3, IAM.1, IAM.3, IAM.4.
  This is the single largest design payload the Librarian commits to
  in the SIR.
- **Raw per-statement / per-grant facts retained alongside aggregates**
  — every Librarian-owned aggregation also exposes its primitive
  inputs under `AssetFact.Properties` or per-statement `RuleFact`
  entries so a future Judge that wants to redo the aggregation can.
- **Per-asset enrichment outputs included** — KMS.2's
  `key_isolation` block is on each asset; the global `KeyUsageIndex`
  does not need to ship to the solver.
- **Judge-owned compounds get raw primitives only** — S3.4, S3.5,
  S3.6, S3.7, KMS.1, ENG.1 do not get pre-aggregated facts. Their
  predicates compose Judge-side over already-typed primitives.

## Decisions for Iteration 4.3 (differential gating)

The aggregation parity check in Prompt 4.3 must verify:

- **AWS S3.** For every fixture: the SIR's `EffectivePermissionFact`
  set per bucket equals the union of the post-aggregation results
  from `S3Properties.ACLsDisabled`, `policy.Document.Assess`,
  `S3Controls.IsPublicAccessFullyBlocked`, and `acl.Assess`. Any
  fixture where the SIR drops a contributing source vs. the legacy
  aggregator fails the gate — the solver would then be reasoning
  over an incomplete effective set.
- **AWS IAM.** For every fixture: the SIR's
  `IdentityFact.Validity[].Permissions` equals
  `iam.Resolve(...).EffectiveAllow` per principal per validity
  window. Privilege classification (`PrivilegeLevel`) must round-trip.
- **AWS KMS.** For every asset with a `cryptography.kms_key_id`: the
  SIR's per-asset `key_isolation` block matches
  `EnrichKeyIsolation`'s output.
- **Cross-domain.** ENG.1 chain firings must round-trip — solver-side
  chain detection on the SIR-exported facts must produce the same set
  of `(chain, asset)` pairs as `risk.DetectChains` on the legacy
  pipeline's failures.

## Open questions / follow-ups

- **Object Lock + Versioning + Retention compound.** Each is currently
  evaluated in isolation (`controls_versioning.go`,
  `retention_object_lock.go`). They jointly determine "is this bucket
  immune to ransomware" but no current control composes them. Future
  control would be Judge-owned (declarative AND of three booleans).
- **WAF + S3 / WAF + endpoint policy.** WAF lives at
  `internal/platform/providers/aws/waf/` and currently has no
  cross-resource compound with S3. If a future control composes "is
  this bucket fronted by a WAF rule that blocks the public ListBucket
  pattern" it would need an `EffectivePermissionFact`-style aggregate
  with WAF rules in the contributing sources — Librarian-owned.
- **CloudFormation drift.** `cfn` provider exists but no compound
  controls combine drift with effective-access yet. Out of scope for
  this audit.

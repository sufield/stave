# Aggregation Ownership: Librarian vs Judge

## Purpose

This document is the contract that drives the SIR design and
the Iter 4.1 differential harness. For every compound check that
combines two or more security vectors into a single verdict, it
records WHICH ENGINE owns the aggregation:

- **Librarian (Stave)** — Stave aggregates the vectors and exposes the
  effective state in the SIR. The Z3 solver reasons over the already-
  combined fact.
- **Judge (Solver)** — Stave exposes raw vectors in the SIR. The Z3
  solver applies the combination rules itself.

**Default rule (REVISED, Iter L0).** Judge aggregates by default. AWS
effective-permission semantics — explicit-deny precedence, condition
keys, cross-account session policies, PAB short-circuit, ACL
ownership rules — are *logic*, not data work. SMT solvers are
purpose-built for this; expressing it in Go is fragile and
duplicates the solver's job. The Phase 2 plan briefly assigned this
to the Librarian; that decision is reversed in this revision because
the resulting "aggregation parity" gate in Iter 4.3 was a tell that
two implementations of the same logic could disagree.

**Librarian's remaining role.** AWS-schema typing — decoding URIs,
ARNs, enum values, parsing condition operators — is data work and
stays in Stave. These are not compounds; they are 1:1 typings of
AWS API constructs into Go types the SIR can serialize.

**Exception.** None at the time of this revision. Future compounds
that are NOT AWS-evaluation-semantics (e.g., a Stave-specific
posture rollup like ENG.1 chain detection) may continue to live
on the Librarian side because their combination rule is Stave's
own product, not AWS's evaluation engine. Each such case must be
documented here with rationale.

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
| **Owner** | **Judge** (revised L0) |
| Rationale | The "either layer can suppress" rule is a logical OR. Stave emits two `PublicAccessBlockFact` rows (account + bucket level) with distinct SourceRefs; the solver composes them. |
| SIR exposure | One `PublicAccessBlockFact` per layer in the resource's `ResourceFactGroup.PAB`. No precomputed "fully blocked" boolean. |

### S3.2 — Effective public exposure (Bucket Policy ∩ ACL ∩ BPA ∩ Ownership)

| Field | Value |
|---|---|
| Check | composed entirely in `python/solver/stave_solver/models/s3.py` per L6 |
| Vectors | resource-based bucket policy + ACL grants + Public Access Block + (optionally) Object Ownership setting |
| Operator | symbolic Z3 formula: `(policy_allow ∧ ¬pab_blocks_policy) ∨ (acl_allow ∧ ¬pab_blocks_acl) ∨ iam_allow`, with explicit-deny precedence and condition-key satisfiability handled by the solver. |
| Resource type | S3 bucket |
| **Owner** | **Judge** (revised L0) |
| Rationale | This is the canonical SMT problem. Stave emits raw per-statement / per-grant / per-PAB-flag facts; the solver composes the formula and either yields a SAT witness (with a `SuggestedFix` per L7) or proves UNSAT. Putting this in the solver eliminates the parity gate that L0 retired. |
| SIR exposure | `ResourceFactGroup` per bucket holding `BucketPolicy []BucketPolicyStatementFact`, `ACLGrants []ACLGrantFact`, `PAB []*PublicAccessBlockFact`, `AttachedIAM []IAMPolicyStatementFact`. Every fact carries a SourceRef that points back at the originating AWS API construct (statement index, grant index, PAB layer). No `EffectivePermissionFact`. No `Suppressed` flag. The chain of reasoning is visible to the user via the `SuggestedFix.changes[].target` SourceRefs the solver emits. |

### S3.3 — Network-scope merge across statements (weakest-wins)

| Field | Value |
|---|---|
| Check | `analysisState.updateWeakestScope` in `s3/policy/analyzer.go:175` |
| Vectors | per-statement `NetworkScope` (VPC condition, IP condition, no condition) |
| Operator | weakest-wins merge across all statements: a single statement without a network condition opens the bucket to the public internet regardless of how restrictive every other statement is |
| Resource type | bucket policy |
| Currently typed | yes — `kernel.NetworkScope` is a typed enum |
| **Owner** | **Judge** (revised L0) |
| Rationale | "Weakest-wins" is a logical OR over per-statement Z3 booleans. The solver is well-suited; encoding it in Stave duplicates AWS evaluation logic. |
| SIR exposure | Each statement's `BucketPolicyStatementFact` carries its `Conditions` (IpAddress / SourceVpc / etc.) verbatim. The solver composes the network-scope formula. |

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
| **Owner** | **Judge** (revised L0) |
| Rationale | Re-implementing this in Z3 is the WHOLE POINT — it is exactly the kind of AWS-evaluation logic SMT solvers are built for. Stave emits per-statement IAM facts (L2) plus SCP / boundary statements as additional vectors; the solver composes them. The "incomplete-when-SCP-missing" semantics become an explicit Z3 incomplete-witness case rather than a hard-coded Librarian fallback. |
| SIR exposure | Per-statement raw vectors: identity-policy `IAMPolicyStatementFact` rows (L2), per-principal SCP and boundary statements (future extension), explicit-deny rows preserved as `Effect=="Deny"` IAMPolicyStatementFacts. No `EffectiveAllow` precomputation. |

### IAM.2 — Privilege classification ladder (admin / elevated / standard / limited / none)

| Field | Value |
|---|---|
| Check | `classifyPrivilege` at `iam/resolve.go:381` |
| Vectors | post-resolution effective grants + `isEffectivelyBroadResource` per grant + admin-action whitelist + service-count threshold |
| Operator | layered classification: `hasAdmin > hasElevated > serviceCount > 2 > else limited / none` |
| Resource type | IAM principal |
| Currently typed | yes — `PrivilegeLevel` enum |
| **Owner** | **Judge** (revised L0) |
| Rationale | The classification ladder is a logical decision tree over typed action sets — Z3-friendly. The thresholds (admin-action whitelist, ≥2 services for "standard") are control-catalog parameters that flow through `ControlFact.Predicate` rather than living in Stave code. |
| SIR exposure | Raw IAM statements per principal (via L2). The solver runs the classification ladder symbolically. |

### IAM.3 — Resource-based policy access index merge

| Field | Value |
|---|---|
| Check | `iam.AddResourcePolicy` at `iam/resource_access.go:35` (extracts), then merged into `ResolvedPermissions.ResourcePolicyGrants` |
| Vectors | per-resource policy statements ∪ per-principal identity policies (cross-account / public detection requires both) |
| Operator | union of grants, with cross-account / public flags computed at merge time |
| Resource type | IAM principal × AWS resource |
| Currently typed | yes — `ResourceAccessEntry`, `ResourcePolicyGrant` |
| **Owner** | **Judge** (revised L0) |
| Rationale | Stave hands the solver every resource-policy statement (per resource) and every identity-policy statement (per principal). The solver computes the cross-account / public-reach question via Z3 boolean composition — same machinery as IAM.1. |
| SIR exposure | Per-resource statements via L1 (S3) and analogous extractors for other resource-based services; per-principal statements via L2. No precomputed cross-account map. |

### IAM.4 — Transitive role chains (`sts:AssumeRole` traversal up to `MaxChainDepth`)

| Field | Value |
|---|---|
| Check | `iam.ResolveChains` at `iam/role_chain.go:59` |
| Vectors | per-principal `sts:AssumeRole` grants + per-role trust policies + per-role resolved permissions + cycle detection + depth cap |
| Operator | bounded transitive closure with cycle detection; final-role permissions become the principal's "transitive admin" set |
| Resource type | IAM principal |
| Currently typed | yes — `RoleChain`, `RoleHop`, `ChainTerminationReason` |
| **Owner** | **Judge** (revised L0) — but with a caveat |
| Rationale | The transitive closure ITSELF is solver-friendly (graph reachability with bounded depth). But the depth cap and cycle detection are operational constraints of the graph traversal, not AWS-evaluation logic. Stave still emits the trust-policy + assume-role grants as raw IAM statement facts; the solver runs reachability over them. The Iter 1.3 `RoleChainSource` produces precomputed `RoleChainFact` rows for now as an optimization; the solver is free to recompute from raw statements when it wants the long-form witness. |
| SIR exposure | Per-principal `IdentityFact.RoleChains []RoleChainFact` (precomputed convenience) AND per-statement IAM facts (raw inputs the solver can recompute from). Both flow through; the solver picks. |

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
| **Owner** | **Judge** (revised L0) |
| Rationale | The per-asset `(kms_key_id, data_classification)` pair is raw Stave data; the "is this key shared across sensitivity levels" question is set comparison — the solver computes it directly from the per-asset pairs. Stave emits each asset's pair untouched; no snapshot-wide index in the SIR. |
| SIR exposure | Per-asset `AssetFact.Properties["cryptography"]["kms_key_id"]` and `tags["data-classification"]` flow through unchanged. The solver builds whatever index it needs. |

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
| **Owner** | **Librarian** (documented exception per L0) |
| Rationale | Stave-product rollup, not AWS-evaluation logic. The kill-chain ordering and per-stage worst-severity rule are Stave's reporting choices; pushing them to the solver buys nothing because they apply to whatever findings the solver returns. |
| SIR exposure | The summary itself does not need to live in the SIR — the solver produces findings, the Librarian rolls them into `AttackStageSummary` for the report. |

### ENG.3 — Exposure ranking (`risk.RankExposures`)

| Field | Value |
|---|---|
| Check | `risk.RankExposures` |
| Vectors | finding base score + chain bonus + duration factor + blind multiplier + blast multiplier |
| Operator | multiplicative composition, sorted descending |
| Resource type | per finding |
| Currently typed | yes — `RankInput`, `ExposureRank`, `ScoreBreakdown` |
| **Owner** | **Librarian** (documented exception per L0) |
| Rationale | Stave-product scoring formula, not AWS-evaluation logic. Ranking is presentation; the solver returns findings, the Librarian ranks them. |
| SIR exposure | None — ranking is a post-solver phase that operates on the findings the solver returned. |

---

## SIR contract (revised L0)

The SIR contains:

- **`ResourceFactGroup` per resource** — one per S3 bucket (and
  analogous structures per service). Each group bundles the raw
  per-statement / per-grant / per-flag vectors:
  `BucketPolicy []BucketPolicyStatementFact`,
  `ACLGrants []ACLGrantFact`, `PAB []*PublicAccessBlockFact`,
  `AttachedIAM []IAMPolicyStatementFact`. No aggregation, no
  precomputed effective-access set, no `Suppressed` flag. The
  solver composes the effective view in Z3.
- **Per-asset properties retained** — `AssetFact.Properties`
  carries asset-level metadata (region, tags, encryption
  configuration, KMS key id, data classification). The solver
  reasons over these directly.
- **SourceRef on every fact** — `BucketPolicyStatementFact.Source.Path`
  is `["Statement", strconv.Itoa(i)]`; `ACLGrantFact` carries
  `["Grants", strconv.Itoa(j), "Permission"]`; PAB facts carry
  `["PublicAccessBlockConfiguration"]` or
  `["AccountPublicAccessBlock"]`; IAM facts carry
  `["IAMPolicy", policyName, "Statement", strconv.Itoa(i)]`.

## Differential gating (revised L0)

The aggregation parity gate that lived in Iter 4.3 is RETIRED.
With aggregation now solver-side, the differential suite compares
"did both engines find the same violations" — full stop. There is
no aggregation step in Stave to compare the solver against.

The Iter 4.1 differential harness still gates on:

- **Same finding set per (control, asset) pair.** A finding the
  CEL engine emits must also be emitted by the solver, and vice
  versa, modulo controls the solver has not yet implemented.
- **SourceRef integrity.** Every solver-emitted finding's
  `contributing_sources` must reference SIR facts that exist in
  the input — no synthetic or aggregated SourceRefs.

## Open questions / follow-ups

- **Object Lock + Versioning + Retention compound.** Each is currently
  evaluated in isolation (`controls_versioning.go`,
  `retention_object_lock.go`). They jointly determine "is this bucket
  immune to ransomware" but no current control composes them. Future
  control would be Judge-owned per the revised default — solver
  composes from the three raw facts already in the SIR.
- **WAF + S3 / WAF + endpoint policy.** WAF lives at
  `internal/platform/providers/aws/waf/` and currently has no
  cross-resource compound with S3. If a future control composes "is
  this bucket fronted by a WAF rule that blocks the public ListBucket
  pattern", Stave emits the WAF rules as raw facts and the solver
  composes — same Judge-default rule.
- **CloudFormation drift.** `cfn` provider exists but no compound
  controls combine drift with effective-access yet. Out of scope.

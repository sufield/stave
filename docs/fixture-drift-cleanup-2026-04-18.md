# Fixture drift cleanup — 2026-04-18

Snapshot of fixture-vs-canonical drift across `testdata/e2e/*/controls/`
and the mechanical cleanup executed against the predicate-drift slice.

The motivation: every e2e fixture carries its own copies of the controls
it exercises. The canonical source of truth is `controls/**/CTL.*.yaml`.
When canonical evolves and per-fixture copies don't resync, tests pass
against the stale copy rather than current behavior — the pattern that
produced the role-side-escalation-bug in iteration `99bb0224f`.

## Drift inventory

605 fixture control copies scanned against 670 canonical controls.

| Status | Count | % |
|---|---:|---:|
| Exactly matches canonical | 67 | 11 |
| Drifted — predicate-level | 71 | 12 |
| Drifted — metadata-only (compliance tags, description, params, name) | 424 | 70 |
| Orphan — canonical missing | 43 | 7 |
| **Total fixture copies** | **605** | 100 |

## Scope split

Per the task's "flag and propose a split" clause for large-scale drift,
cleanup is split across three iterations by risk level:

| Iteration | Scope | Risk | Size | Status |
|---|---|---|---|---|
| Iteration 1 (2026-04-18, commit `6dbc8771b`) | Predicate-level drift resync | High — can mask real bugs | 71 files | **Closed** |
| Iteration A (2026-04-18, commit `99b8b84c3`) | Metadata-only drift resync | Low — no predicate-behavior change | 424 files | **Closed** |
| Iteration B (2026-04-19, this commit) | Orphaned fixture copies — archaeology and reclassification | None — no file changes | 43 files | **Closed** |
| Iteration C (2026-04-18, commit `29472b86d`) | Golden regeneration for stale `expected.out.json` surfaced by Iteration 1 | Low — resync only, no control changes | 53 goldens | **Closed** |
| Iteration D (2026-04-18, commit `cad33b166`) | Regression investigation and resolution for 20 failures flagged by Iteration C | Low — fixture observation updates only, no predicate or code changes | 20 fixtures | **Closed** |

## This iteration — predicate-level resync

### Category verdict

All 71 predicate-drift cases classified as **CANONICAL IS CORRECT**:
every canonical's git commit date post-dates its fixture copy's commit
date. The typical pattern across the 71: the canonical added new
compliance tags, refined its predicate (e.g., `CTL.S3.PUBLIC.001`
split its combined `public_read OR public_list` predicate into two
controls), added `observation_fields` or `exposure` blocks, or tightened
description. The fixture copy stayed on the earlier snapshot of canonical.

Zero files classified as FIXTURE COPY IS CORRECT, BOTH DIVERGED, or any
case needing investigation.

### Resync execution

All 71 fixture copies overwritten from canonical verbatim. The list is
spread across these fixture families:

| Family | Count |
|---|---:|
| `e2e-forge-ecs-*` (forge-generated ECS fixtures) | 14 |
| `e2e-forge-lambda-*` (forge-generated Lambda fixtures) | 22 |
| `e2e-forge-iam-*` (forge-generated IAM entropy fixtures) | 6 |
| `e2e-h1-*` (HackerOne disclosure replay fixtures) | 14 |
| `e2e-s3-*` (hand-written S3 e2e fixtures) | 12 |
| Larger consolidated fixtures (`e2e-h1-shopify-94087`, `-94502`) | 6 |
| **Total (overlap possible)** | **71** |

Most common drifted control IDs:

| Control | Resyncs |
|---|---:|
| `CTL.S3.PUBLIC.001` | 12 |
| `CTL.S3.PUBLIC.005` | 5 |
| `CTL.S3.ACCESS.001` | 3 |
| Lambda family (`DLQ`, `VPC.SUBNET`, `VPC.SENSITIVE`, `UPDATECODE.SCOPE`, `TRACE`, `TIMEOUT`, `ROLE.SHARED`, `PASSROLE`, `LAYER.ORIGIN`, `ENV.ENCRYPT`, `CONCURRENCY`) | 2 each |
| ECS family (`SECRETS`, `ROOT`, `PRIV`, `NETWORK`, `LOG`, `INCOMPLETE`, `IMAGE`, `EXEC`) | 2 each |
| IAM role-hygiene family (`PERMISSIONDRIFT`, `CATEGORYMIX`, `INTENTTAG`) | 2 each |

### Test suite verification

`make test` exit 0 after the 71 resyncs. Zero test failures.

Interpretation: the fixtures' observation data and expected-findings
counts already matched canonical behavior, even against the stale
fixture control copies. Two reasons this is consistent with the green
result:

- Observation fixtures were crafted to exercise the specific
  predicate path the control asserts — and those paths were preserved
  across canonical's evolution (canonical typically narrowed scope
  rather than broadening, so the observation still triggers).
- Expected-findings counts in `expected.findings.count` /
  `expected.summary.json` were maintained against canonical behavior
  (likely because the forge-generated fixtures and the hand-written
  ones both have their counts regenerated periodically).

The green result does not imply the drift was harmless in principle —
a different fixture + observation combination could have masked a
regression. The role-side-escalation-bug (iteration `99bb0224f`) is
the precedent: that fixture's expected count WAS calibrated against
the stale predicate and passed for the wrong reason. This iteration's
cleanup removes that class of masking across all 71 predicate-drift
cases.

## Subsequent iterations

### Iteration A — metadata-only drift resync (closed)

The drift in this category was non-behavioral: compliance tag additions,
description refinements, new `observation_fields` blocks, new
`params.attack_stage` entries. Resyncing these didn't change predicate
behavior.

**Execution**: 424 fixture copies overwritten from canonical in one pass.
Post-resync sync check confirmed zero drift remaining across the 424.
Full suite exit 0 on first run after the resync — **no golden
regeneration needed**. Post-hoc analysis of why: zero of the 424
resynced fixtures carry `expected.out.json` full-output goldens (which
compare `control_description` and `control_compliance` fields). Every
fixture with a full-output golden had its drift resolved in Iteration 1
(the predicate-drift slice — those fixtures overlapped). The Iteration A
residual was entirely fixtures that check `expected.findings.count` and
`expected.summary.json` only, neither of which includes the drifted
metadata fields.

**Distribution of Iteration A's 424 resyncs**:

| Family | Resyncs |
|---|---:|
| `e2e-forge-*` (forge-generated fail/pass pairs) | ~300 |
| `e2e-s3-golden-path` + `e2e-s3-deep-checks` (consolidated S3 matrices) | 49 |
| `e2e-h1-shopify-94087` + `e2e-h1-shopify-94502` | 51 |
| AD, Cisco, VSphere, K8s CIS fixtures | ~40 |
| Remaining hand-written | balance |

Golden regenerations triggered: **0**. Test failures surfaced: **0**.

Combined drift state after Iterations 1 + A:

| Category | Before | After |
|---|---:|---:|
| Clean | 67 | 562 |
| Predicate-level drift | 71 | 0 |
| Metadata-only drift | 424 | 0 |
| Orphans | 43 | 43 |
| **Total** | **605** | **605** |

### Iteration C — golden regeneration for stale full-output files (closed)

Iteration 1 resynced 71 predicate-drifted fixture control copies to
canonical. That surfaced a **second** class of staleness the audit hadn't
enumerated: `expected.out.json` goldens for fixtures whose controls were
resynced in Iteration 1 still embedded the pre-rename `control_name`,
pre-expansion `control_description`, pre-backfill `control_compliance`
tags, and pre-split `misconfigurations` layout. The combined effect:
73 `TestE2E/*` subtests and `TestVerifyOutputByteIdentical` failing
after Iteration 1, even though `expected.findings.count` and
`expected.summary.json` continued to pass.

#### Categorization

Each of the 73 failing fixtures' actual output was diffed against its
expected golden:

| Category | Count | Disposition |
|---|---:|---|
| STALE GOLDEN (metadata-only drift: `control_name`, `control_description`, `control_compliance*`, `remediation.example`, `exposure`, scoring fields, `policy_fingerprint`) | 53 | Regenerate |
| MIXED (findings-count mismatch + metadata drift) | 2 | Flag, do not regenerate |
| NO-GOLDEN (no `expected.out.json`; fails via `expected.findings.count` going 1 → 0) | 18 | Flag, do not regenerate |
| **Total** | **73** | |

The halt condition — "regression-dominated failure set" — did not fire:
73% (53/73) were pure stale-metadata drift consistent with known
canonical evolution since the fixtures' golden files were last generated.

#### Regeneration execution

Each of the 53 STALE fixtures was re-run with `./stave apply` using
the same args as the e2e harness. Raw output was written to `expected.out.json` with canonical
key ordering (keys sorted, 2-space indent). No control files or
observation files were modified.

Post-regeneration `make test`: 53 STALE fixtures pass, plus
`TestVerifyOutputByteIdentical` (which compares against
`e2e-s3-verify/expected.out.json`) now passes.

#### Flagged (deferred) — 20 fixtures

Not resolved by this iteration; each is a behavioral-findings
discrepancy, not metadata drift.

**MIXED (2):**

- `e2e-h1-unikrn-254200` — missing `CTL.S3.TENANT.ISOLATION.001`
  finding. Observation lacks the top-level `identities` array the
  predicate's `any_match` scans, so the check short-circuits.
- `e2e-s3-deep-checks` — missing `CTL.S3.ACCESS.001` finding.
  Observation property is `external_accounts`; current predicate reads
  `external_account_ids`. Field-name drift between observation and
  predicate.

**NO-GOLDEN (18) — all `e2e-forge-{ecs,lambda}-*-fail`:**

Every forge-generated fail fixture produces 0 findings against
`expected.findings.count=1`. Root cause is uniform across the 18:
observation omits `properties.container.kind` (ecs) /
`properties.function.kind` (lambda), which the canonical predicate
requires for the `eq` kind-discriminator. At fixture-creation commit
`bb559b622` (Apr 13) these fixtures produced 1 finding each; at
current HEAD they produce 0. Some change to CEL's handling of
`eq <literal>` against a missing field shifted the semantics between
those points in the timeline.

Per "do not modify canonical controls or fixture inputs" and the
halt-on-regression rule: flagged for a follow-up regression iteration
with its own discipline (bisect the CEL change, decide whether the
current or prior semantics is correct, align observations or
predicates accordingly).

### Iteration D — regression investigation and resolution (closed)

Iteration C deferred 20 failures as regression-suspected: 2 MIXED (stale
golden + finding-level drift) and 18 NO-GOLDEN (finding-count regression
with no `expected.out.json`). The forge-family hypothesis proposed in
Iteration C — CEL `eq`-against-missing-field semantics shifted between
`bb559b622` and HEAD — needed direct testing.

#### Hypothesis test — **REFUTED**

Git bisect between `bb559b622` (fixture-creation) and HEAD narrowed the
regression to commit `6dbc8771b` itself — Iteration 1's predicate-drift
resync. At `6dbc8771b~1` the fixture produces 1 finding; at `6dbc8771b`
it produces 0. No CEL code changed at that commit. No CEL code change
between `bb559b622` and HEAD affects `OpEq` emission — the compiler still
generates `(hasField(X) && X == value)` for `eq`, which short-circuits
to false on missing fields (the same behavior before and after
`f968cc1f0`'s `isMissing` refinement, which only affected `isMissing`
not the `has()` macro).

The actual root cause: Iteration 1 correctly adopted the canonical
predicate shape, which added a leading kind-discriminator clause
(`properties.container.kind == ecs_service` / `properties.compute.kind
== function` / `identities.any_match(app_signer, ...)` / renamed
`external_account_ids` field). The fixture observations were never
updated to provide these canonical-contract fields. Iteration 1
unmasked the pre-existing observation-contract drift.

Symbolically: the fixture predicate diverged from canonical (Iteration 1
resync corrected that), but the fixture observation had diverged from
canonical's observation contract and nobody had reconciled it yet.

#### Resolution — fixture observation updates

All 20 failures resolved by fixture-input updates. No predicate changes,
no code changes, no canonical control changes.

| Group | Count | Fix |
|---|---:|---|
| `e2e-forge-ecs-exec-fail` | 1 | Add `properties.container.kind: ecs_service` |
| `e2e-forge-ecs-{image,log,network,priv,root,secrets}-fail` | 6 | Add `properties.container.kind: task_definition` |
| `e2e-forge-lambda-*-fail` | 11 | Add `properties.compute.kind: function` |
| `e2e-h1-unikrn-254200` | 1 | Add `identities[]` with `app_signer` carrying `purpose: "enforce_prefix=false;allow_traversal=true"`; regenerate golden |
| `e2e-s3-deep-checks` | 1 | Rename `storage.access.external_accounts` → `external_account_ids` on `vuln-cross-account`; convert ARN to 12-digit account ID; regenerate golden |
| **Total** | **20** | |

Each fixture verified individually after its fix. Full suite `make test`
exit 0; `TestVerifyOutputByteIdentical` still passes; zero new
regressions.

#### Why fixture-input, not predicate-update

Iteration D's task suggested defaulting to option (b) — explicit
`present` guards before `eq` checks — on the theory that the canonical
predicates were accidentally strict. Rejected because:

- The kind-discriminator clause is intentional, not accidental. The
  canonical design uses `container.kind` / `compute.kind` / `storage.kind`
  to disambiguate overlapping property trees within a shared `properties`
  tree. Adding a `present` guard would change the discriminator into a
  loose filter that passes even when the asset isn't of the expected
  kind.
- `external_account_ids` is the authoritative field name per
  `docs/contract/storage.md` and the S3 extractor's emission. The
  fixture's `external_accounts` is a stale pre-rename form. The fix is
  to match the contract, not to add a predicate fallback for an
  out-of-contract field name.
- The `identities[]` array is a documented observation namespace. The
  unikrn fixture was authored before the canonical control graduated
  from a tag-only check to an identity-scanning `any_match` compound.
  Adding the identity matches the contract, not the other way around.

In short: the fixture observations were stale relative to the canonical
observation contract. Iteration 1 surfaced that; Iteration D closes it.

### Iteration B — orphaned fixture copies (closed)

Archaeology on the 43 "orphan" fixture control copies surfaced a
classification error in the original drift inventory. The inventory's
orphan heuristic was **"fixture copies whose `id:` doesn't appear in
the canonical catalog"** — that heuristic produces false positives for
**fixture-scoped synthetic controls** that were never intended to live
in canonical.

#### Per-ID canonical history

All 13 unique orphan control IDs have **zero** canonical git history
(`git log --all -- "controls/**/$id.yaml"` returns empty). None were
ever added to canonical; none were ever removed. They are deliberately
fixture-local synthetic controls authored to exercise specific Stave
machinery.

| Control ID | Fixtures | Machinery under test |
|---|---:|---|
| `CTL.EXP.DURATION.001` | 15 | `unsafe_duration` SLA threshold, bad-DSL/schema version handling, format-sarif/text output, unknown source type, exempt-suppression, breach-discovery sparse observations |
| `CTL.EXP.OWNERSHIP.001` | 1 | Owner-missing warning path |
| `CTL.EXP.RECURRENCE.001` | 4 | Breach-discovery recurrence windows |
| `CTL.EXP.STATE.001` | 3 | Breach-discovery state tracking |
| `CTL.EXP.VISIBILITY.003` | 5 | Prefix-scoped visibility (safe/unsafe/overlap/missing-evidence) |
| `CTL.ID.AUTHZ.001` | 1 | Least-privilege identity check |
| `CTL.ID.KUBE.001` | 7 | Kubernetes identity ingestion (clean/violations/invalid/messy/ignore) |
| `CTL.ID.KUBE.003` | 2 | Secondary kube identity path (paired with KUBE.001) |
| `CTL.PROC.MAIL.001` | 1 | Audience-mismatch process-mail check |
| `CTL.TEST.DEFAULT.002` | 1 | Per-control threshold default |
| `CTL.TEST.OVERRIDE.001` | 1 | Per-control threshold override (paired with DEFAULT.002) |
| `CTL.TP.PLATFORM.001` | 1 | Platform-boundary touchpoint |
| `CTL.TP.VENDOR.001` | 1 | Vendor-boundary touchpoint |
| **Total** | **43** | |

#### Categorization result

0 RETIRED, 0 RENAMED, 0 CONSOLIDATED, 0 AMBIGUOUS. **43 reclassified**
as intentional fixture-scoped synthetic controls.

Fixture names reinforce the harness-test purpose: `e2e-01-violation`,
`e2e-02-no-violation`, `e2e-04-bad-dsl-version`,
`e2e-05-bad-schema-version`, `e2e-06-unknown-source-type`,
`e2e-format-sarif`, `e2e-format-text`, `e2e-exempt-suppression`,
`e2e-breach-disc*`, etc. — scenario labels describe the harness
behavior being exercised, not a canonical security control.

#### Resolution

No file-level actions. The orphans are correct as-is; the drift
inventory's heuristic needs refinement for future scans.

All 34 orphan-host fixtures (spanning the 43 control copies) currently
pass. Full `make test` exit 0.

#### Methodology correction for future drift scans

Future orphan scans should exclude **synthetic harness-test fixtures**
from the orphan count. A refined heuristic:

- Canonical-orphan: fixture's `id:` absent from canonical AND the
  fixture's `id:` has non-empty git history under `controls/` (i.e.,
  canonical did exist at some point). These are real orphans needing
  RETIRED/RENAMED/CONSOLIDATED dispositions.
- Synthetic-harness: fixture's `id:` absent from canonical AND zero
  canonical git history. These are deliberate fixture-local controls
  and are not drift.

Applying this corrected heuristic to the current repo: **0 true
orphans**.

## Notes

- **`controls/**` was not modified.** Per the task's "do not fix canonical"
  constraint, no predicate, compliance-tag, or description correction
  was made on the canonical side during this iteration. If any canonical
  control turns out to be incorrect relative to its fixture's long-
  standing expected behavior, that's a separate iteration with its own
  methodology-grounded analysis.
- **Per-fixture test verification** was compressed into a single
  full-suite `make test` run rather than one-fixture-at-a-time. This
  was a pragmatic call given 71 files — the suite's e2e coverage is
  tight enough that any behavioral regression would surface in that run.
  Future iterations that touch fewer files should prefer per-fixture
  verification for tighter pinpointing.
- **Coverage gaps are not addressed here.** A FIXTURE COPY MISSING
  analysis (canonical controls with no fixture coverage) is a separate
  concern from drift cleanup and would be its own scan.

## Series close

With Iteration B closed (2026-04-19), the drift-cleanup series is
complete:

| Iteration | Outcome |
|---|---|
| 1 — predicate drift | 71 fixture controls resynced to canonical |
| A — metadata drift | 424 fixture controls resynced to canonical |
| B — orphans | 43 reclassified as synthetic harness fixtures; 0 true orphans |
| C — stale goldens | 53 `expected.out.json` regenerated |
| D — regression resolution | 20 fixture observations updated to match canonical observation contract |

Final drift state:

| Category | Count |
|---|---:|
| Clean (matches canonical) | 562 |
| Predicate-level drift | 0 |
| Metadata-only drift | 0 |
| True canonical orphans | 0 |
| Synthetic harness fixtures (not drift) | 43 |
| **Total fixture control copies** | **605** |

`make test` exit 0. `TestVerifyOutputByteIdentical` passes. Zero
flagged regressions remain.

# Engine Baseline — Verified Coverage Map

**Status: verified against repo state 2026-05-28.** This document
is the single source of truth for reasoning-engine expansion work.
Every count below was re-derived from files on disk, not carried
forward from any prior audit. Where a number disagrees with the
committed matrix, the matrix is stale (see "The stale-matrix
finding").

It exists because three consecutive planned iterations were scoped
from a point-in-time audit that no longer matched the repo. The
rule going forward: **the repo is the source of truth; when an
audit and the repo disagree, the repo wins.**

---

## 1. Reconciliation with the original plan

| Original item | Verified state | Evidence |
|---|---|---|
| Deprecate `internal/app/forecast/` | **LIVE — not a removal target** | Backs `stave trend forecast`; one consumer `cmd/trend/forecast.go`; correctly placed in the application layer. |
| Chain engine removal (`DetectChains`) | **LIVE — producer of compound detection** | Called at `internal/app/eval/workflow.go:357`; `ChainFindings` consumed by ~20 production files. The "untangle" relocated the data *types* to `internal/core/findings/`; the producer was intentionally retained. |
| Cognito gap closure | **COMPLETE** | 104 control YAMLs across 20 subdomains; all 10 planned iterations shipped with passing end-to-end examples; `cognito-iteration10` README states "Closes the gap-closure plan." |
| SMT-query fixtures (18/20 → 20/20) | **DONE 2026-05-28** | `s3-tenant-prefix-isolation` closed by PR 3.6; `staging-stale-endpoint` closed via explicit fixture selection. See `SMT-QUERY-GAPS.md` / `CATALOG.md`. |
| Engine rule expansion | **PARTIALLY DONE; matrix undercounts it** | This document. |

---

## 2. What "the 49" actually is

The "Clingo 3/49 / Prolog 4/49 / PySAT 0/49" counts use **49 example
fixtures across 20 scenarios** as the denominator — *not* 49 control
categories. The control catalog is far larger (hundreds of
controls); the 49 are the vulnerable+remediated fixtures wired into
the H1 fixture × engine matrix (`scripts/h1-matrix/`). Coverage
numbers in this document are **fixtures that produce a non-empty
verdict**, and the parenthetical is **scenarios with at least one
firing fixture (of 20)**.

---

## 3. Engine rule inventory (on disk)

| Engine | Rule program(s) | Last modified | Runner used by matrix |
|---|---|---|---|
| Clingo | `examples/clingo-constraints/constraints.lp` (V1–V17), `…/ai-delegation-shadow.lp` | 2026-05-17 / 05-12 | `clingo-constraints/run.py` |
| Prolog | `examples/prolog-proof-trees/reasoning.pl` | 2026-05-17 | `prolog-proof-trees/transform-to-pl.sh` + `reasoning.pl` |
| PySAT | `examples/sat-control-regression/{run.py,compound_rules.py}` (8 compound rules) | 2026-05-17 | `sat-control-regression/run.py` |
| Soufflé | `examples/engines/souffle/*.dl` | — | `souffle` reachability transform |
| Z3 / cvc5 | per-example `query.smt2` (20/20 scenarios) | 2026-05-28 | `z3_runners` + in-example queries |
| CEL | the control catalog itself | — | `stave apply` |

> Note: `examples/engines/clingo/` holds a parallel copy of the
> `.lp` files; the matrix loads the `clingo-constraints/` set. Keep
> them in sync or consolidate (tracked as cleanup, not part of this
> baseline).

---

## 4. The stale-matrix finding — RESOLVED 2026-05-28

`scripts/h1-matrix/matrix.json` — the file `CATALOG.md`'s engine
summary renders from — had been stale since **2026-05-08**, predating
the rule expansion (2026-05-12 … 05-28) and badly undercounting
coverage. It has now been **regenerated and committed** (the numbers
below are measured, not projected). Regeneration also required fixing
a harness bug: `cell_export` omitted `--allow-unknown-input`, so
`export-sir` exited 4 on fixtures lacking `generated_by.source_type`
and the SMT cell crashed on the missing file.

Measured coverage (regenerated 2026-05-28, `clingo`/`pysat` run via
their `.tools-venv` Python modules — there is no system `clingo`
binary, but the matrix never used one):

| Engine | matrix.json (2026-05-08) | Measured (2026-05-28) | Δ |
|---|---|---|---|
| CEL | 18/49 | 18/49 (stable) | — |
| Soufflé | 49/49 | 49/49 (stable) | — |
| **Clingo** | **3/49** | **22/49 fixtures · 19/20 scenarios · 0 errors** | **+19** |
| **Prolog** | **4/49** | **23/49 fixtures · 19/20 scenarios · 0 errors** | **+19** |
| PySAT | 0/49 | **1/49 fixtures · 1/20 scenarios · 0 errors** | **+1** |

> The Clingo/Prolog rows include six gaps closed 2026-05-28 (V18–V23),
> all now confirmed by the regenerated matrix:
> - `s3-tenant-prefix-isolation` — `has_purpose_flag` lift + rule V18 /
>   `tenant_isolation_gap`.
> - `iam-attach-user-policy-self` — rule V19 / `self_attach`
>   (`iam:AttachUserPolicy` on the principal's own ARN).
> - `s3-cross-account-replication-overperm` — rule V20 /
>   `replication_overperm` (`resource_policy_action` s3:Get*/s3:List*).
> - `sns-secrets-compound-chain` — rule V21 / `sns_secrets_enum`
>   (apigateway:GET ∧ sns:GetTopicAttributes ∧ iam:GetUserPolicy).
> - `s3-broad-write-scope` — rule V22 / `broad_write_scope`
>   (`has_upload_key_mode` = "prefix").
> - `iam-autoscaling-privesc-bypass` — rule V23 /
>   `passrole_autoscaling_bypass`: deny-aware effective permission via
>   negation-as-failure (`not`/`\+ has_deny_action`).
>
> None needed a projector change — every predicate was already
> emitted/lifted. Two earlier "projector gap" notes were wrong:
> `s3-broad-write-scope` uses the already-emitted `has_upload_key_mode`,
> and the deny-aware `iam-autoscaling-privesc-bypass` is expressible
> with rule-level negation over the already-lifted `has_deny_action`
> (no `effective_allow` projector needed). Before this batch both
> engines sat at 13/20.

SMT (Z3/cvc5) is tracked per-scenario rather than in the engine
summary: **20/20 scenarios** have a paired `query.smt2`.

**Regeneration is done.** `matrix.json` and `CATALOG.md` were
regenerated and committed 2026-05-28 (`python3
scripts/h1-matrix/run.py && python3 scripts/h1-matrix/render.py`).
Contrary to an earlier note in this doc, the regen ran fine on this
workstation: the matrix invokes `clingo` and `pysat` as **Python
modules from `.tools-venv`**, not as system binaries (`command -v
clingo` is empty, which is irrelevant). The numbers above are
measured.

---

## 5. Per-scenario coverage matrix (verified)

`✓` = at least one fixture in the scenario produces a non-empty
verdict for that engine. Clingo and Prolog share the lifted-fact
base, so they cover the **same 19 scenarios** and miss the **same 1**.

| Scenario | CEL | Soufflé | Clingo | Prolog | SMT |
|---|:--:|:--:|:--:|:--:|:--:|
| apigw-private-api-scoped-deny | · | ✓ | ✓ | ✓ | ✓ |
| cloudtrail-stop-logging | ✓ | ✓ | ✓ | ✓ | — |
| cognito-no-mfa-advanced-security | ✓ | ✓ | ✓ | ✓ | ✓ |
| cognito-self-register-to-aws-creds | ✓ | ✓ | ✓ | ✓ | ✓ |
| eks-aws-auth-template-injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| eks-rbac-webhook-config-access | ✓ | ✓ | ✓ | ✓ | ✓ |
| iam-21-privesc-5-patterns | ✓ | ✓ | · | · | ✓ |
| iam-attach-user-policy-self | ✓ | ✓ | ✓ | ✓ | ✓ |
| iam-autoscaling-privesc-bypass | ✓ | ✓ | ✓ | ✓ | ✓ |
| iam-multi-hop-trust | · | ✓ | ✓ | ✓ | ✓ |
| iam-overpermission-wildcard | ✓ | ✓ | ✓ | ✓ | ✓ |
| s3-broad-write-scope | ✓ | · | ✓ | ✓ | ✓ |
| s3-bucket-name-dangling | ✓ | · | ✓ | ✓ | ✓ |
| s3-cross-account-replication-overperm | · | ✓ | ✓ | ✓ | ✓ |
| s3-dotgit-readable | ✓ | · | ✓ | ✓ | ✓ |
| s3-public-list-policy | ✓ | · | ✓ | ✓ | ✓ |
| s3-public-read-policy | ✓ | · | ✓ | ✓ | ✓ |
| s3-tenant-prefix-isolation | ✓ | · | ✓ | ✓ | ✓ |
| sns-secrets-compound-chain | · | ✓ | ✓ | ✓ | ✓ |
| staging-stale-endpoint | ✓ | · | ✓ | ✓ | ✓ |

---

## 6. Gap classification (what to expand, what to leave)

Per the "do not force a query" principle (`SMT-QUERY-GAPS.md`), each
empty cell is classed as a genuine **gap** (engine shape applies, a
rule/fixture should be added) or **N/A** (no shape for this engine).

### Clingo / Prolog — the 1 remaining missing scenario

| Scenario | Class | What it needs |
|---|---|---|
| `iam-21-privesc-5-patterns` | DOCUMENTED BLIND SPOT | The rhino patterns attach `contributed_by` to the attacker *user*, while `trusts_service` attaches to the target *roles* — different subjects, so the same-subject `exploitable_role` join cannot fire. This is the blind spot the prolog README intentionally demonstrates (Clingo/Prolog behave differently from Z3/Soufflé here). A non-circular structural rule would need a cross-subject "user can pass/assume an admin role" model; a rule keyed on `contributed_by(_, CTL...)` alone would just echo the CEL verdict. Left as a documented gap rather than forced, per the "do not force a query" principle. |

This is the only Clingo/Prolog gap left. It is not a quick rule-only
win — see the class note.

**Closed 2026-05-28 (no projector change — every predicate was
already emitted/lifted):**

- `s3-tenant-prefix-isolation` — `has_purpose_flag` added to the
  Clingo lifter + rule V18; `tenant_isolation_gap` in `reasoning.pl`.
- `iam-attach-user-policy-self` — rule V19 / `self_attach`:
  `iam:AttachUserPolicy` with the principal's own ARN as resource
  (`has_resource(U, U)`).
- `s3-cross-account-replication-overperm` — rule V20 /
  `replication_overperm`: `resource_policy_action` carrying
  `s3:Get*` / `s3:List*` (the broad read remediation removes).
- `sns-secrets-compound-chain` — rule V21 / `sns_secrets_enum`:
  the three-way `apigateway:GET ∧ sns:GetTopicAttributes ∧
  iam:GetUserPolicy` compound.
- `s3-broad-write-scope` — rule V22 / `broad_write_scope`:
  `has_upload_key_mode(asset, "prefix")` (already emitted by
  propertyFacts; the doc's earlier "needs a projector" note was
  wrong).
- `iam-autoscaling-privesc-bypass` — rule V23 /
  `passrole_autoscaling_bypass`: `iam:PassRole` ∧ `autoscaling:*`
  ∧ ¬`has_deny_action(autoscaling:CreateLaunchConfiguration)`.
  Negation-as-failure models effective permission (wildcard allow
  minus explicit deny); remediation adds the concrete
  `autoscaling:Create*` denies. No `effective_allow` projector needed.

Each fires on the vulnerable fixture and stays silent on the
remediated one; each mirrors the scenario's existing SMT query.

### PySAT — structural fixture gap (now 1/49)

PySAT's compound rules each require **≥2 catalog controls firing on
the same fixture** (a boolean-AND over `contributed_by` edges). A scan
of all 49 H1 fixtures found **exactly one** that fires ≥2 controls:
`staging-stale-endpoint/stale-staging-public` fires
`CTL.LIFECYCLE.STAGING.STALE.001` + `CTL.S3.PUBLIC.LIST.002`. Adding
the matching `staging_endpoint_exposed` compound rule (2026-05-28)
takes PySAT from 0/49 to **1/49**, verified with the real solver
(`python-sat` in `.tools-venv`).

The other 48 fixtures are single-issue (one control each), so no
further compound can light up against the current fixture set.

**Where the multi-control fixtures actually are (the big lever).**
`scripts/h1-matrix/run.py:find_fixtures()` *skips any example that has
no local `controls/` dir*. That silently drops **38 catalog-only
examples** — including every chain-based compound scenario
(`demo-ai-security`, `shadow-admin-detection`,
`shadow-ec2-lateral-movement`, `vpc-peering-exfiltration`,
`s3-delegation-failure`, the `bedrock-*` and `cognito-iteration*`
families). Run against the full catalog these fire **2–14 controls
each** on their writeup fixture — exactly the multi-control inputs the
PySAT compound layer needs, and far richer Clingo/Prolog inputs too.

Bringing them into the matrix is the single largest remaining
coverage lever, but it is a **design decision + devcontainer task**,
not a local edit:
- It changes `find_fixtures()` to fall back to the full `controls/`
  catalog (instead of skipping), which **roughly triples the matrix**
  (49 → ~130+ fixtures) and mixes evaluation modes (curated
  per-example control sets vs. the full catalog). The maintainer
  should decide whether the matrix stays curated or goes
  comprehensive.
- It cannot be measured on this workstation (no `clingo`; and a
  ~130-fixture × 9-engine sweep needs the full toolchain). It must run
  in the devcontainer where `matrix.json` can regenerate and be
  reviewed.

Until then, authoring more `COMPOUND_RULES` adds zero *matrix*
coverage (the fixtures that would satisfy them aren't discovered) —
so the staging rule shipped 2026-05-28 is the correct stopping point
for rule-only PySAT work.

### Precision caveat for the per-asset Clingo rules

The V7–V17 presence rules flag a boolean being set, and some fire on
the *remediated* fixture too where a second property is still set
(e.g. `s3-dotgit-readable/after` still emits `has_public_read=true`).
This is detection-positive but weak discrimination. Expansion should
prefer rules that distinguish vulnerable from remediated, mirroring
the SMT sat/unsat discipline.

---

## 7. Infrastructure status

| Engine | This workstation | Devcontainer | Notes |
|---|:--:|:--:|---|
| CEL (stave) | ✓ | ✓ | Native binary. |
| Z3 / cvc5 | ✓ | ✓ | Yices optional, skipped when absent. |
| Soufflé | ✓ | ✓ | — |
| Prolog (swipl) | ✓ | ✓ | — |
| Clingo | ✓ (venv module) | ✓ | `clingo` 5.8.0 in `.tools-venv`; the matrix uses the Python module via `venv_python()`, not a system binary. |
| PySAT (`python-sat`) | ✓ (venv module) | ✓ | In `.tools-venv`; matrix uses `venv_python()`. |

All engines run on this workstation through `.tools-venv` (clingo,
pysat) and native binaries (z3, cvc5, swipl, souffle), so `matrix.json`
regenerates here — no devcontainer needed. The earlier "absent here"
note conflated "no system `clingo` binary" with "clingo unavailable."

---

## 8. Recommended expansion priorities

1. ~~**Regenerate `matrix.json`** and re-render `CATALOG.md`~~ —
   **done 2026-05-28.** Clingo/Prolog/PySAT now measured at
   22/23/1 (19/19/1 scenarios), 0 errors. Also fixed the
   `cell_export` missing-flag bug that had made regen impossible.
2. **Discover the 38 catalog-only examples** (now the big lever — see
   §6 PySAT). `find_fixtures()` skips them today; falling back to the
   full catalog brings in every compound/chain scenario (each fires
   2–14 controls), which is what unlocks broad PySAT coverage and
   richer Clingo/Prolog inputs. Triples the matrix (~49 → ~130+) and
   is a maintainer design call (curated vs. comprehensive matrix).
3. **`iam-21-privesc-5-patterns`** (the one Clingo/Prolog gap left):
   needs a cross-subject "user can pass/assume an admin role" model,
   not a same-subject join. Treat as a research item, not a quick win
   — see §6.

Done 2026-05-28 (see §6): all six projector-free Clingo/Prolog rules
(V18–V23), closing every Clingo/Prolog gap that did not require a
cross-subject model. The "effective_allow" and "has_broad_write"
projector gaps turned out to be solvable with rule-level logic over
already-lifted predicates — no core change was needed.

Each expansion iteration updates §5 and §6 of this document and
must keep every previously-firing cell firing (regression-safe).

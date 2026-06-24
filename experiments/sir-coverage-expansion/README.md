# Experiment: SIR Coverage Expansion

## Status
**CLOSED — Phase 1 + Phase 2 measured.** Default stays `curated`.
Conclusion: `--allowlist-mode full` / `auto_prop_*` adds no capability a
reasoning engine doesn't already have, because `ObservationFacts` already
exports every observation scalar (all join keys) under its dotted path,
unconditionally, in both modes. Phase 2 (Z3 wall-time, dense worst-case,
consumer rule) is in `phase2/`; decision + watch-list at the bottom.

## Question

Can the SIR export auto-generate its scalar allowlist from the
predicate index (every property any control reads becomes an
exported fact) without pushing Z3 solving time past acceptable
limits?

The original concern: hand-maintained `propertyAllowlist` in
`cmd/exportsir/facts.go` overlaps only ~41 of the 2,954 control-
relevant property paths in the catalog (1.4%). Auto-generation
could close that gap mechanically. The fear was that 100× more
facts would push Z3 solving time from milliseconds to seconds or
minutes.

## What's implemented

`stave export-sir --allowlist-mode full` (default: `curated`).

In `full` mode, a new projector `autoPropertyFacts` walks the
predicate index for each observed asset type and emits one
triple per (path-the-catalog-reads, asset, scalar value):

    auto_prop_<sanitized_path>(asset_id, value)

The `auto_prop_*` namespace is separate from the curated has_*
predicates, so downstream solvers reading `has_public_read` /
`can_assume` / `has_allow_action` are unaffected. They see new
unfamiliar predicates and ignore them unless they choose to
consume them.

## Measurements

Run with `--now 2026-05-09T00:00:00Z` against shipped demo
fixtures:

| fixture                              | curated | full | delta | growth |
|--------------------------------------|--------:|-----:|------:|-------:|
| cognito-iteration2/cross-resource    |    5358 | 5366 |    +8 |  0.15% |
| cognito-iteration10/writeup          |    5366 | 5384 |   +18 |  0.34% |
| shadow-admin/writeup                 |    5354 | 5361 |    +7 |  0.13% |
| s3-delegation/writeup                |    5358 | 5365 |    +7 |  0.13% |
| demo-ai-security/writeup             |    5373 | 5396 |   +23 |  0.43% |

## Why the growth is so small

The premise of the experiment — "more paths in the allowlist =
many more triples" — was wrong. The catalog reads 2,954 distinct
property paths across all asset types, but each shipped fixture
populates only a handful of paths per asset (the ones its
scenario actually needs). Auto-generation walks the index but
can only emit a triple where the OBSERVATION has a value at that
path; missing data produces no fact (closed-world default).

The 1% scalar-coverage number from Experiment 2 of the audit was
a **catalog-side** measurement — paths the catalog COULD read.
The fact-export size is bounded by **observation-side** data —
paths the snapshot actually contains. Shipped demos are sparse.
A maximally-dense snapshot where every catalog path is populated
would produce roughly 6× the current triple count (2,954 paths ×
~10 assets), not 100×.

## What this means for the original decision

The risk that motivated keeping the allowlist hand-curated
("auto-generation will blow up solver runtime") does not
materialize on shipped fixtures. Two consequences:

1. **The honest scope statement still holds.** Auto-generation
   doesn't suddenly make Z3 verify the full catalog. It emits
   facts for paths the observation populates — which is a tiny
   subset of paths the catalog reads. The proof scope is still
   "what the SIR projects," and the SIR projects what the
   observation contains.

2. **Flipping the default is cheap, but not yet useful.** The
   `auto_prop_*` predicates aren't consumed by any shipped
   solver query. Adding them to the default export would grow
   the triple count by single-digit percentages while producing
   no new verdict. Worth doing only when a solver query needs a
   predicate the auto-projector emits.

## Phase 2: measured

Scripts to reproduce live in `phase2/`. Run on a host with `z3` and
`souffle` installed.

### Z3 wall-time impact — the proxy was misleading in a deeper way

The expectation ("indistinguishable delta, because the new predicates
don't appear in any query") assumed Z3 *completes*. It does not. A bare
`(check-sat)` over the open-world SIR base is **5,453 ground String-atom
assertions under `(set-logic ALL)`** (no quantifiers), and Z3's time is
**super-linear in fact count**:

| facts | result | z3 time |
|------:|--------|--------:|
|   200 | sat     | 0.32 s |
|   500 | sat     | 1.31 s |
| 1,000 | sat     | 4.83 s |
| 2,000 | **timeout** | >15 s |
| 5,452 | **timeout** | >15 s |

The cliff is ~1,500 facts; every shipped fixture's base is ~5,000+.
So Z3 `check-sat` **times out in both curated and full mode** — the
curated-vs-full delta is moot because *neither completes*. This is
exactly what the SIR export header already says: `recommended: souffle,
clingo (enumeration at scale); scoped_queries: z3, cvc5`. Z3 is the
wrong engine for the whole base regardless of allowlist mode; the
+0.1–0.4% extra `auto_prop_*` facts are irrelevant next to that.

### Dense-fixture worst case — and a correction to the estimate

The "10 assets × 2,954 paths = 29,540" estimate was wrong about the
*shape*: the projector is **asset-type-scoped** (an `aws_s3_bucket`
asset emits `auto_prop_*` only for the S3 paths S3 controls read, not
IAM/AI paths it happens to carry). The real per-asset ceiling is the
**max paths a single type's controls read = 135** (Step Functions),
not 2,954. Across all types there are **1,489 distinct (type, path)
read-pairs**.

`phase2/gen_dense_fixture.py` builds the true worst case (K assets per
type, every path of that type populated):

| fixture | assets | curated | full | auto_prop added | growth |
|---|--:|--:|--:|--:|--:|
| shipped (sparse) | ~3 | ~5,460 | ~5,485 | ~23 | 0.1–0.4% |
| dense K=1 | 134 | 7,601 | 9,087 | 1,486 | 19.5% |
| dense K=10 | 1,340 | 27,284 | 42,144 | 14,860 | 54% |

Even the K=10 base (42k triples, larger than the old 29,540 estimate)
is handled by Soufflé in **under 2 seconds**, where Z3 times out at 9k:

| engine | base | wall time |
|---|--:|--:|
| z3 (`check-sat`) | 9,087 | **timeout (>15 s)** |
| souffle | 27,284 (curated) | 525 ms |
| souffle | 42,144 (full) | 1,829 ms |

Full mode costs ~3.5× the curated souffle time at this synthetic worst
case — but still sub-2-second, and the worst case is far denser than any
real fixture. The cost concern that motivated hand-curating the
allowlist does not materialize for the recommended engine.

### Real consumer — and the finding that closes the experiment

`phase2/to_souffle.py` translates the SIR jsonl to Soufflé facts and adds
a rule that joins a Bedrock knowledge base to a PHI-classified bucket *by
ARN* — a cross-resource verdict single-asset CEL cannot express:

```prolog
kb_ingests_phi(KB, B) :-
  ai_knowledge_base_target_bucket_arn(KB, B),     // KB's target bucket
  storage_tags_data_classification(B, "phi").     // that bucket is PHI
```

The verdict fires (`(…knowledge-base/PATIENTKB, arn:aws:s3:::patient-records)`).
**But it fires in `curated` mode too** — which kills the case for `full`:

> A third projector, **`ObservationFacts`**, emits a fact for *every*
> scalar leaf in the observation under its literal dotted path
> (`ai.knowledge_base.target_bucket_arn`, `storage.tags.data-classification`,
> …) and is appended **unconditionally in both allowlist modes**
> (`internal/core/sirfacts/observation_facts.go`).

So the raw join-key primitives a reasoning engine needs are **already
exported in `curated` mode**. The 23 `auto_prop_*` facts a full export adds
to `demo-ai-security` are the *same 23 scalars* `ObservationFacts` already
emits under dotted names — `auto_prop_*` is a **sanitized-name alias of a
subset** of an always-on stream (`ObservationFacts` emits *more*: all
leaves, not just catalog-read ones). Verified: the rule above run against
the dotted `observationFacts` predicates returns the verdict in `curated`
mode (1 row). An earlier draft of this section claimed "fires only in
full mode" — that was an artifact of naming the rule after `auto_prop_*`;
corrected here.

### Verdict — close it

`--allowlist-mode full` / `auto_prop_*` provides **no capability a
reasoning engine doesn't already have in `curated` mode.** Phase 2 proved
the cost concern was unfounded (souffle handles the worst case in <2s; z3
was never viable on the full base in either mode), *and* that the feature
is redundant with the always-on `ObservationFacts` export. The only thing
`auto_prop_*` offers over the dotted stream is pre-sanitized predicate
names — an ergonomic nicety any translator (like `to_souffle.py`) already
handles. There is no verdict to chase: a downstream consumer should read
the dotted `observationFacts` predicates, which need no allowlist flag at
all.

## How to reproduce

    # Baseline
    stave export-sir --observations <fixture> --format jsonl \
        --now 2026-05-09T00:00:00Z | wc -l

    # Auto-augmented
    stave export-sir --observations <fixture> --format jsonl \
        --allowlist-mode full --now 2026-05-09T00:00:00Z | wc -l

    # Which auto_prop_ predicates fired
    stave export-sir --observations <fixture> --format jsonl \
        --allowlist-mode full --now 2026-05-09T00:00:00Z \
        | jq -r 'select(.predicate | startswith("auto_prop_")) | .predicate' \
        | sort -u

## Pre-flight checklist when someone picks this up

- [x] `--allowlist-mode (curated|full)` flag exists with
      curated as the default — no behavior change for shipped
      consumers
- [x] Auto-generated predicates live in a separate namespace
      (`auto_prop_*`) so they never collide with curated has_*
- [x] Measurement on shipped fixtures: 0.13% – 0.43% growth
- [x] Z3 wall-time measurement on both modes — z3 times out on the
      open-world base in BOTH modes (cliff ~1,500 ground String atoms;
      bases are ~5,000+); delta moot. Souffle is the engine at scale.
- [x] Synthetic dense fixture (`phase2/gen_dense_fixture.py`):
      worst case is type-scoped (max 135 paths/type, 1,489 type-path
      pairs); K=10 → 42,144 triples, souffle 1.8 s vs z3 timeout.
- [x] First downstream consumer (`phase2/to_souffle.py`, rule
      `kb_ingests_phi`, a KB→PHI-bucket join by ARN) — works, but fires
      in `curated` mode too via the always-on `ObservationFacts` dotted
      predicates. `auto_prop_*` is redundant with that stream, so the
      consumer needs no allowlist flag. Experiment closed (see below).

## Decision & action items

The Phase 2 data resolves the original question. Outcome:

1. **Do NOT flip the default to `full`, and do NOT build a generic
   `auto_prop_*` consumer.** Cost was never the blocker (Phase 2), and
   `auto_prop_*` is redundant with the always-on `ObservationFacts`
   dotted stream — it grants no new capability. Default stays `curated`
   (verified: `--allowlist-mode` defaults to `curated`; no code change).

2. **Experiment CLOSED** with the finding above. Not "dead weight that's
   expensive" (the Phase 1 fear) and not "valuable but unconsumed" (the
   Phase 1 framing) — it is *redundant*: the raw primitives ship
   unconditionally under dotted names already.

3. **Need a raw property in a solver? Read the dotted `observationFacts`
   predicate — no allowlist change required.** Every scalar leaf is
   exported in both modes (e.g. `ai.knowledge_base.target_bucket_arn`,
   `storage.tags.data-classification`). Sanitize dotted→underscore for
   Soufflé (see `phase2/to_souffle.py`). The curated `has_*` allowlist
   (`internal/core/sirfacts/observation_facts.go`) is *governance naming*
   for a few predicates, not the gate on raw access; extend it only if
   you want a stable named predicate, never to "unlock" a property.

4. **Watch-list — cross-resource join keys** (for designing new compound
   detections; all already exported via `observationFacts`). Of 3,014
   catalog-read paths, 100 are join-key-named; these 12 carry raw value
   keys (the rest are booleans / pre-derived signals):

   | path | already covered by |
   |---|---|
   | `ai.knowledge_base.target_bucket_arn` | `compute.bedrock.role_reaches_phi_bucket` (pre-derived) |
   | `cryptography.kms_key_id`, `storage.encryption.kms_key_id` | `CTL.KMS.CONCENTRATION` / `CTL.KMS.ISOLATION` |
   | `storage.access.external_account_ids` | S3 cross-account / delegation controls |
   | `storage.replication.destination_region` | sovereignty / region-SCP controls |
   | `cdn.waf_web_acl_id` | `CTL.CLOUDFRONT.WAF.001` |
   | `api.integration.lambda_arn` | trigger-auth / ghost-lambda controls |
   | `compute.deployment.{apigw,eb}_targets_alias_arn` | alias/deployment controls |
   | `governance.data_classification`, `reachability.anonymous_path.target_data_classification` | foothold / exposure `reaches_sensitive` |
   | `auth.webhook.identity_mapping.uses_access_key_id` | (niche; no control today) |

   "Already covered" is a catalog read, not an exhaustive audit — vet a
   specific candidate against the control catalog before building. The
   only one with no obvious existing control is the webhook access-key
   mapping; if a compound detection ever needs it, the fact is already
   in the export.

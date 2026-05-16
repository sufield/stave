# Experiment: SIR Coverage Expansion

## Status
**Phase 1 implemented and measured.** Default behavior unchanged.

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

## Phase 2: not yet started

Open questions for the next person who picks this up:

- **Z3 wall-time impact.** Triple count is a proxy, not the
  metric. Run `time z3 facts.smt2 +query.smt2` on the four
  fixtures above in both modes; report the wall-time delta.
  Expectation: indistinguishable, because the new predicates
  don't appear in any query.
- **Dense-fixture worst case.** Construct a synthetic fixture
  where every catalog path is populated on every asset (e.g.
  10 assets × 2,954 paths = 29,540 auto-generated triples).
  Measure Z3 wall time vs the current ~5,000-triple baseline.
- **Real consumer.** Write a Soufflé / Clingo rule that uses
  `auto_prop_*` to derive a verdict that the curated predicates
  can't express today. If no such rule exists, the auto-projector
  is dead weight regardless of cost.

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
- [ ] Z3 wall-time measurement on both modes (run on a host
      with Z3 installed; not part of CI)
- [ ] Synthetic dense fixture to establish worst-case bound
- [ ] First downstream consumer that uses `auto_prop_*` —
      until this exists, the experiment is exploratory

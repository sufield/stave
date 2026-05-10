# Perturbation Analysis — Before/After Snapshot Diff + Impact

Closes the loop on "I changed an IAM policy / a bucket tag / a
trigger Lambda — what unsafe states did this change introduce
or resolve?" Reads two SIR fact exports, computes the exact
fact-set delta via deterministic `fact_id`, then runs the
catalog's `forbidden_state` queries against each side and
reports verdict flips.

```
stave export-sir (before, after)            → JSONL fact pairs
diff.py JSONL pair                          → delta.json (added / removed / unchanged)
stave export-invariants                     → invariants.json
impact.py obs pair + invariants + delta     → impact.json (regressions, improvements)
```

## What the tool answers

For each `forbidden_state` query in the catalog, did the
perturbation:

| Verdict flip | Meaning |
|---|---|
| `unsat → sat` | **REGRESSION** — perturbation introduced a new reachable unsafe state |
| `sat → unsat` | **IMPROVEMENT** — perturbation closed a previously reachable unsafe state |
| `sat → sat`   | no change — reachable before, reachable after |
| `unsat → unsat` | no change — safe before, safe after |

Both flip cases attach the fact-set delta from `diff.py` so
each verdict change is traceable to specific added / removed
facts (with `fact_id`, `subject`, `predicate`, `object`,
`evidence`, `provenance.property_path`).

## Demo fixture: external-account access on a PHI bucket

Reuses `examples/z3-forbidden-state/fixtures/writeup-config`
(PHI bucket + external account ID) vs `remediated-config`
(same bucket with `external_account_ids` cleared). The
forbidden_state on `CTL.S3.ACCESS.EXTERNAL.ORG.001`
distinguishes them.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/perturbation-analysis/run.sh
```

Expected:

```
Computing fact-set delta ...
  N → N facts (+0/-2, N unchanged)

Running queries against before / after observations ...
  1 queries: 0 regressions, 1 improvements, 0 unchanged

=== Resolved unsafe states ===
{
  "query": "CTL.S3.ACCESS.EXTERNAL.ORG.001.query.smt2",
  "before": "sat",
  "after": "unsat",
  "removed_fact_count": 2
}
```

The 2 removed facts are the `contributed_by(<bucket>,
CTL.S3.ACCESS.*)` exposure facts that disappear when the
external-account predicate stops firing on the bucket. Each
carries `provenance.property_path` so the diff traces back to
the source observation property
(`contributing_controls` on the temporal exposure window).

## Architecture: why the impact step uses `obs_to_facts`

The diff step happily reads the full SIR JSONL — 5000+ facts
per snapshot, the larger the better for traceability.

The impact step does NOT run queries against the full SIR
SMT-LIB export. Stave's SMT export emits closed-world axioms
for every predicate it declares (so absence-of-fact is
provably distinct from "predicate true on something not
asserted"). With 2592 controls' worth of predicates and 5000+
facts, Z3 takes minutes-to-never to discharge the universals.

The impact step instead reuses
`examples/z3-forbidden-state/obs_to_facts.py` to emit a
fact file binding only the property variables the
`forbidden_state` queries reference. That output is small
(typically 5–20 lines), Z3 finishes in milliseconds, and the
verdict is identical to what the full SIR would produce
because the forbidden_state predicates are scoped to those
properties anyway.

The two layers serve different purposes:

- **Diff layer (full SIR JSONL)** — traceability and
  attribution. Every observation property change surfaces as
  one or more added / removed `fact_id`s with provenance.
- **Impact layer (focused SMT facts)** — verdict
  comparison. Only the predicates the queries care about are
  bound; Z3 runs quickly.

Both layers share the same `fact_id` vocabulary so the
attribution from the diff still aligns with the verdict flip
from the impact.

## Constraints (matches the iteration plan)

- **External tool only** — no Stave core changes. `diff.py`,
  `impact.py`, and `run.sh` live in `examples/`.
- **Reads existing exports** — `stave export-sir --format jsonl`
  for the diff side, `stave export-invariants` for the
  catalog of forbidden_state queries.
- **Does not generate new queries** — the same auto-generated
  forbidden_state queries from `examples/z3-forbidden-state/`
  drive the impact step.
- **`fact_id` is the join key** — set differences on
  fact_ids, not text comparison. Identical
  (subject, predicate, object) → identical `fact_id`,
  guaranteed by the deterministic SHA-256 derivation.

## What this de-risks

A developer who edits an observation (or whose collector
re-captures after a real config change) gets an answer in
**seconds** that names:

1. Which facts were added / removed (with property-path
   provenance).
2. Which forbidden_state queries flipped.
3. The attribution between the two — added / removed
   `fact_id` lists on each flip.

Today's "diff two `stave apply` outputs by hand" workflow
gives you finding counts. This tool gives you **causal
attribution** — exactly which property change moved exactly
which invariant from reachable to unreachable (or vice versa).

## Future extensions (out of scope)

- **CI/CD gate** — wrap `run.sh` in a GitHub Action;
  fail-fast if any forbidden_state query flips
  `unsat → sat` between the PR's before/after observations.
- **Cross-engine impact** — today only the Z3-backed
  forbidden_state queries flip. A future iteration runs
  Clingo / PySAT / Datalog queries the same way.
- **Multi-perturbation analysis** — given N changes, isolate
  which individual change caused each flip via shrinking
  (similar to mutation testing).

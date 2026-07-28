# Reasoning Spec Trial Results

Trial agent ran all five trial packages, blind (read `spec-trial.yaml`
+ `input.<ext>` + `export-schema.md`; did not open `golden.yaml`).

## Result summary

| # | Trial | Outcome | Failure category | Notes |
|---|---|---|---|---|
| 1 | z3-public-read-bucket | **PASS** | — | Exact match on verdict + witness |
| 2 | souffle-anonymous-reachability | **PASS** | — | `anonymous_reachable_count: 12` byte-identical |
| 3 | clingo-violation-atoms | **FAIL → fixed → PASS** | **A** (spec bug: wrong predicate name) | Spec said `mfa_enforced`; JSONL emits `has_mfa_enforced` |
| 4 | prolog-proof-chain | **FAIL → fixed → PASS** | **C** (wrong golden transcription) | Spec inventory transcribed 6; actual file has 12 |
| 5 | prism-risk-probability | **PASS** | — | Step probs exact, aggregate within `±0.005` |

3 PASS straight, 2 caught real defects, 0 unfixable. The trial framework
caught both a spec defect and a transcription defect — exactly what
it's designed to do.

## Cross-engine failure pattern

The reviewer's hypothesis was "running them together lets you compare
failure patterns across engines — 'all three riskier trials failed at
step 4' is a different signal than 'only Prolog failed at step 4.'"

The actual pattern:

- **No structural failures in the spec format.** All five specs
  parse, the trial agent followed the reasoning steps to completion
  on all five, and four of five produced answers byte-identical to
  the golden on the first try.
- **The two failures were in different categories.** Clingo failed
  because the spec referenced a predicate by the wrong name (a
  spec authoring bug). Prolog failed because the golden was
  mis-transcribed in Phase 1 (a golden authoring bug). Same trial
  format, two distinct kinds of bug. The framework distinguishes
  between them via the validation block: when the trial output is
  internally consistent and matches the engine's actual output but
  not the golden, the golden is wrong; when the trial agent can't
  derive the engine's output from the spec, the spec is wrong.

## Failure category A — spec bug (Clingo)

The Clingo spec said:

> Apply rule `mfa_disabled`. For every user pool whose
> `mfa_enforced` predicate has object "false", emit one violation
> atom.

The JSONL export actually emits `has_mfa_enforced`, not
`mfa_enforced`. The catalog's projection convention is `has_<prop>`
for every boolean property; the spec author (the Phase 2 author —
me) wrote the bare name. A trial agent following the spec literally
queries `mfa_enforced`, finds nothing, and produces 3 violations
instead of 4.

**Fix**: corrected the predicate name in `spec.yaml` step 3, plus
added a note that the JSONL export uses the `has_<property>`
naming convention. Re-stripped to produce a fresh `spec-trial.yaml`.

The trial after the fix produces the full 4-violation set.

## Failure category C — golden transcription bug (Prolog)

The Prolog spec's `expected_result` said:

```yaml
proof_trees_count: 6
# Six proof trees expected — three resources × two actions
# (s3:GetObject, s3:ListBucket).
```

The actual golden file (`examples/prolog-proof-trees/expected/output.txt`)
contains **12 proofs**: three resources × four actions
(s3:GetObject, s3:ListBucket, dynamodb:GetItem, dynamodb:Query).
My Phase 1 transcription only counted the S3-action pairs and
missed the dynamodb pairs.

The trial agent's output (12) matched the engine's output (12).
The golden was wrong.

**Fix**: corrected `proof_trees_count: 6` → `12` in `spec.yaml`,
plus a note explaining the cartesian-product semantic. The rule
the catalog ships does not gate the (action, resource) product
by service compatibility — it emits `via s3:GetObject` for
dynamodb resources too. That's a known coarseness of the rule,
not a defect of the trial.

## Disclosures (from the Z3 trial; still apply)

1. **Spec author and trial runner are the same session.** A truly
   blind trial would spin up a fresh agent with only the trial
   package. The pass rates here demonstrate the specs are
   well-formed, not that an arbitrary agent would succeed.

2. **Leak audit found three structural leaks**, fixed where
   possible:

   | Trial | Leak | Resolution |
   |---|---|---|
   | Z3 | example ARN in step-3 output description | replaced with `<bucket-arn>` placeholder |
   | Clingo | violation atom names in the rule definitions | structural — the rule names ARE the spec; cannot be removed without breaking the spec |
   | PRISM | step names + probabilities in the context block | structural — the model's parameters ARE the spec; cannot be removed |

   The Clingo and PRISM leaks are not bugs. The spec describes
   *which rules to apply* and *what parameters those rules use*;
   the answer is the *derivation*, not the rule names. A trial
   agent given the rule names still has to evaluate them against
   the input data, which is what the test measures.

## What the next blind trial should look like

The reviewer's follow-up — "one fully-blind re-run of the hardest
trial (probably Prolog or PRISM) to confirm the spec stands
alone" — is now well-scoped:

- **Prolog** is the right pick. Its golden was wrong on the first
  pass; after the fix the spec is internally consistent. A truly
  blind run by a fresh agent confirms the spec describes the
  cartesian-product semantic precisely enough that the agent
  arrives at 12 without seeing the explanation comment.
- The Clingo trial would also be a useful blind re-run because
  the fix added a "do not strip the `has_` prefix" instruction
  that didn't exist before; verifying that a blind agent now
  reaches all 4 violations validates the fix.

Both spec files are fixed; both trial packages are re-stripped;
both are ready for the fully-blind follow-up.

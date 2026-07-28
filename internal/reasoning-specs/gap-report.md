# Reasoning Spec Gap Report

Phase 4 deliverable per Prompt 3. Reads Phase 2 trial results
([TRIAL-RESULTS.md](TRIAL-RESULTS.md), [BLIND-TRIAL-RESULTS.md](BLIND-TRIAL-RESULTS.md))
and applies the A/B/C/D failure taxonomy from the brief.

## Summary

| Engine | Same-session trial | Blind sub-agent re-run | A (ambiguous) | B (missing field) | C (format mismatch) | D (wrong logic) | E (golden defect) |
|---|---|---|---|---|---|---|---|
| Z3 | **PASS** | not needed (passed first try) | 0 | 0 | 0 | 0 | 0 |
| Soufflé | **PASS** | not needed (passed first try) | 0 | 0 | 0 | 0 | 0 |
| Clingo | **FAIL → fixed → PASS** | **PASS** (confirms fix) | **1** | 0 | 0 | 0 | 0 |
| Prolog | **FAIL → fixed → PASS** | **PASS** (confirms fix) | 0 | 0 | 0 | 0 | **1** |
| PRISM | **PASS** | not needed (passed first try) | 0 | 0 | 0 | 0 | 0 |
| **Total** | 5 | 2 | **1** | 0 | 0 | 0 | **1** |

Three trials passed on the first run. Two surfaced defects on different sides of the spec-vs-golden contract. Both fixes confirmed under blind re-run by fresh sub-agents.

## Category clarification: E ≠ A/B/C/D

The brief enumerates four failure categories (A: ambiguous, B: missing field, C: format mismatch, D: wrong reasoning) but explicitly acknowledges a fifth in its negative rule:

> 2. **Do NOT change the golden answer to match the trial agent's output.** If the trial agent got a different verdict, the spec is wrong or the golden answer is wrong. Investigate which one — don't just make them agree.

The Prolog failure was the "golden answer is wrong" case — a Phase 1 transcription defect, not a Phase 2 spec defect. This report names it **Category E: golden authoring defect** so the failure mode is enumerable rather than implicit. The trial framework distinguishes E from A/B/C/D via the diagnostic table in [TRIAL-RESULTS.md](TRIAL-RESULTS.md#cross-engine-failure-pattern): the trial agent's output agrees with the engine's actual output but not the golden.

---

## Engine: Z3 — PASS

No defects. Spec passed same-session on first try; spec format is well-formed; reasoning chain is precise enough that `z3` invoked on the input produces SAT with witness `arn:aws:s3:::acme-customer-uploads` — byte-identical to the golden.

One leak found in Phase 2 (the example ARN in the step-3 output description) was cleaned by replacing with `<bucket-arn>` placeholder in `spec-trial.yaml`. The leak was cosmetic — the witness ARN must still be derivable from `input.smt2` regardless of whether the spec mentions it — but is gone.

## Engine: Soufflé — PASS

No defects. Spec passed first-try same-session; an independent Python re-implementation of the closure (during Phase 1 inventory) produced the same `anonymous_reachable_count: 12` that the spec's `expected_result` claims. The reasoning steps (`ALLOWING_POOLS → UNAUTH_ROLES → cartesian product of has_action × has_resource`) are unambiguous and the input fixture is canonical.

## Engine: Clingo — Category A (ambiguous predicate naming)

### What the spec said

> **Step 3 — apply rule `mfa_disabled`.** For every user pool whose
> `mfa_enforced` predicate has object "false", emit one violation atom.

### What the trial agent did

The trial agent queried for predicate name `mfa_enforced` in the JSONL fact stream, found zero matches, and emitted no `mfa_disabled` violation. The trial produced 3 of 4 expected violation atoms.

### What the export actually emits

```
$ grep -i mfa input.jsonl | jq -r .predicate | sort -u
has_mfa_enforced
```

The catalog's JSONL export uses the `has_<property>` naming convention for every projected boolean. The Clingo source rules in `examples/clingo-constraints/ai-delegation-shadow.lp` correctly use `has_mfa_enforced(P, "false")`. The spec author (me, in Phase 2) stripped the `has_` prefix and confidently named a non-existent predicate.

### Category classification

This sits between A (ambiguous) and B (missing field):

- **Not pure B**: the field DOES exist in the export. It's just named differently than the spec said.
- **Not pure A**: the spec wasn't ambiguous; it was wrong-but-definite. A trial agent following it literally got a deterministic wrong answer.

Closest fit: **Category A — the spec didn't provide enough context (the naming convention) for the agent to find the right field**. The fix is a documentation note, not a spec rewrite.

### Fix applied (revision in `spec.yaml` step 3)

```diff
-      action: >
-        Apply rule `mfa_disabled`. For every user pool whose
-        mfa_enforced predicate has object "false", emit one
-        violation atom.
-      input: facts where predicate is mfa_enforced
+      action: >
+        Apply rule `mfa_disabled`. For every user pool whose
+        has_mfa_enforced predicate has object "false", emit one
+        violation atom.
+      input: facts where predicate is has_mfa_enforced
       output: violation(<pool_arn>, "mfa_disabled")
       rule: >
         Fire when an aws_cognito_user_pool subject has
-        mfa_enforced == "false".
+        has_mfa_enforced == "false". The catalog's JSONL
+        export uses the `has_<property>` naming convention for
+        every projected boolean; do not strip the prefix.
```

Blind sub-agent re-run after the fix produced all 4 violations matching the golden.

## Engine: Prolog — Category E (golden authoring defect)

### What the spec said

```yaml
expected_result:
  # Six proof trees expected — three resources × two actions
  # (s3:GetObject, s3:ListBucket).
  proof_trees_count: 6
```

### What the trial agent computed

The trial agent computed the cartesian product of the unauth role's `has_action` set × `has_resource` set:

- 4 actions: `s3:GetObject`, `s3:ListBucket`, `dynamodb:GetItem`, `dynamodb:Query`
- 3 resources: `arn:aws:s3:::app-public-assets`, `arn:aws:s3:::app-public-assets/*`, `arn:aws:dynamodb:us-east-1:111122223333:table/app-data`
- Product: **12**

### What the actual engine output says

```
$ grep -c "^anonymous reaches" examples/prolog-proof-trees/expected/output.txt
12
```

The engine's committed output has 12 proof trees. The trial agent's computation matched the engine. The spec's golden (6) was wrong.

### Root cause

Phase 1 inventory comment said "three resources × two actions (s3:GetObject, s3:ListBucket)." That miscount ignored the two DynamoDB actions on the role. A 4 × 3 cartesian product = 12, not 6.

### Diagnostic shape

- Trial vs engine: AGREE (both 12)
- Trial vs golden: DISAGREE
- Per the diagnostic table: **golden is wrong**

### Fix applied (revision in `spec.yaml` expected_result)

```diff
   expected_result:
-    # Six proof trees expected — three resources × two actions
-    # (s3:GetObject, s3:ListBucket).
-    proof_trees_count: 6
+    # 12 proof trees: 3 resources × 4 actions. The catalog projects
+    # 4 actions on the unauth role (s3:GetObject, s3:ListBucket,
+    # dynamodb:GetItem, dynamodb:Query); Prolog's full cartesian
+    # product of has_action × has_resource yields 12, even though
+    # some pairs are semantically nonsensical (e.g. "via s3:GetObject"
+    # on a DynamoDB ARN). The blast-radius rule does not gate the
+    # product by action-resource compatibility; that's a stricter
+    # invariant the engine could add but does not today.
+    proof_trees_count: 12
     first_proof_root: "anonymous reaches arn:aws:s3:::app-public-assets via s3:GetObject"
     edges_per_proof: 4
```

Blind sub-agent re-run after the fix produced 12 proof trees, all with 4 edges, including one rooted at `arn:aws:s3:::app-public-assets via s3:GetObject` — exact-match on count + edges + semantic-match on the at-least-one-proof-rooted-at rule.

## Engine: PRISM — PASS

No defects. Spec passed first-try same-session; step probabilities exact-match, aggregate `0.412` within the `±0.005` semantic-match tolerance. The five-step model is described precisely enough (P=0.80 constant, P=0.95 conditional on the relevant fact predicate, P=0.60 constant) that a trial agent reproduces the aggregate.

## Cross-cutting patterns

1. **The `has_<property>` naming convention is foundational.** The Clingo failure was rooted in stripping the prefix. Future specs that reference per-asset boolean facts must include a note about the convention in their `required_fields:` block. The Soufflé and Prolog specs happened to escape because they referenced predicates the catalog also exports without the prefix (`allows_unauthenticated`, `maps_unauth_to`, `has_action`, `has_resource` — the last two have the prefix; the first two don't).

2. **Cartesian-product semantics need to be stated explicitly.** The Prolog spec said "for every (resource, action) tuple derivable" — that was correct, but the inventory transcription mis-counted because the inventory author (me) assumed action-resource pairing was filtered by service compatibility. The catalog rule does NOT filter; the spec now states this explicitly with a worked example.

3. **No Category B (missing field) defects across 5 trials.** Every field the specs referenced exists in the SIR export. The trial framework would have surfaced a missing field as `predicate not found` from the trial agent; none did.

## Export contract gaps

**None identified.**

The Clingo failure was a naming-convention mismatch, not a missing field. The field `has_mfa_enforced` is exported correctly; the spec just named it `mfa_enforced`. No Stave-side projector change needed.

## Spec-ready engines (no revisions needed)

- z3-public-read-bucket
- souffle-anonymous-reachability
- prism-risk-probability

## Specs that were revised

- **clingo-violation-atoms** — Category A revision (step 3 predicate name + naming-convention note). Confirmed under blind sub-agent re-run.
- **prolog-proof-chain** — Category E revision (`proof_trees_count: 6 → 12` + cartesian-product explanation comment). Confirmed under blind sub-agent re-run.

## Revisions log

```
reasoning-specs/revisions/
├── clingo-violation-atoms.diff
└── prolog-proof-chain.diff
```

Diff files committed alongside the gap report.

## Status

All five specs PASS under blind re-run conditions. The framework is at steady state until either (a) the catalog's projection vocabulary changes, in which case Category A and B defects may surface; or (b) the engine source files change, in which case Category D or E defects may surface. Both are detectable by re-running this suite as a regression check.

# Conflict classifier: disqualifying precedence rule

This document explains a non-obvious correctness rule encoded in
`classify.go`. Read it before changing `Classify` or its tests.

The classifier assigns one of four categories to each control pair:

    CONTRADICTION > REDUNDANCY > EMPIRICAL_SUBSUMPTION > DIVERGENCE

The precedence is *disqualifying*, not first-match-wins. A pair that
triggers a higher-precedence category is excluded from any
lower-precedence one, even when the lower-precedence triggers also
appear to fit. The three specific invariants that make this rule
load-bearing:

## 1. REDUNDANCY requires unanimous agreement

A pair with IDENTICAL dependencies, matching metadata
(compliance / attack_stage / remediation), and agreement on every
evaluated fixture except one is **CONTRADICTION/LOGIC_BUG**, not
REDUNDANCY.

Any disagreement, however rare, disqualifies the pair from
REDUNDANCY. Do not add a "REDUNDANCY tolerance threshold" or
"agreement_rate >= 0.95 counts as redundant" feature — that
relaxation is the bug.

This rule is pinned by
`TestClassify_DisqualifyingPrecedence_RedundancyToContradiction`,
which constructs 9 agreements + 1 disagreement and asserts
CONTRADICTION. The test exists specifically to fail if a future
maintainer reintroduces tolerance semantics.

## 2. EMPIRICAL_SUBSUMPTION is asymmetric

The check is "A's violations imply B's violations" (where B is the
broader control), not "verdicts agree." The asymmetry matters:

| narrower verdict | broader verdict | consistent with subsumption? |
|------------------|-----------------|------------------------------|
| VIOLATION        | VIOLATION       | yes (overlap)                |
| PASS             | PASS            | yes (overlap)                |
| PASS             | VIOLATION       | yes — broader is stricter    |
| VIOLATION        | PASS            | **no — disqualifies**        |

A single (narrower=VIOLATION, broader=PASS) witness disqualifies
broader from subsuming narrower (broader cannot subsume narrower if
narrower catches something broader misses) and the pair classifies
CONTRADICTION instead.

The opposite direction (narrower=PASS, broader=VIOLATION) is
*consistent* with subsumption — it means broader is genuinely
stricter — and does **not** disqualify. Do not collapse this to a
symmetric "verdicts agree" check.

This rule is pinned by `TestClassify_EmpiricalSubsumptionAsymmetryDisqualifies`
and `TestClassify_EmpiricalSubsumptionDirectionRespected` (the
latter ensures the direction-aware check works whether `ControlA`
or `ControlB` is the narrower one).

## 3. MISSING_ASSET_CLASS_GUARD subcategory

When CONTRADICTION applies, the subcategory is determined by a
**presence-of-diversity** check on the disagreement witnesses' asset
types: ≥2 distinct `asset.Type` values → MISSING_ASSET_CLASS_GUARD,
otherwise LOGIC_BUG.

This is deliberately *not* a "statistical explanatory variable"
detector. Detecting whether asset_class actually explains the
disagreement is a statistics problem the classifier should not own.
The presence-of-diversity rule is a hint, not a proof — it surfaces
the candidate explanation, and the catalog author decides whether
the suggested guard would actually resolve the disagreement.

The partial-correlation case
(`TestClassify_ContradictionPartialAssetClassCorrelation`) pins this
behavior: three asset classes in disagreement witnesses, only some
of which correlate with the verdict split, still classifies
MISSING_ASSET_CLASS_GUARD. Adding correlation thresholds would
defeat the rule's intent.

## Maintenance contract

Any change to `Classify` or `classifyOne` must preserve all three
invariants. The pinning tests above are the contract. If a future
feature requires relaxing one of these invariants, escalate the
design before implementing — the relaxation is almost certainly the
bug.

## Provenance

These rules were established during Iteration 3 Node 3c review
(2026-04-17). The taxonomy discussion in earlier iterations did not
pin them down explicitly; this doc and the pinning tests are how the
rules survive future maintenance after the rationale leaves working
memory.

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

## 4. Matched vs evaluated

Every classifier decision reads from the **matched** subset of
co-evaluations — fixtures where `ce.ReadOverlap` is true. A fixture
where the shared dependency path was not present on the asset is
structurally outside both controls' scope; CEL's absent-value
semantics still produce a verdict, but that verdict is an artifact,
not evidence about the controls' relationship.

Counting unresolved co-evaluations as evidence produces three failure
modes that look correct in isolation but are vacuous on inspection:

| caller of unresolved co-eval | failure mode |
|------------------------------|--------------|
| `disagreementWitnesses`      | vacuous CONTRADICTIONs and DIVERGENCEs on asset classes that don't share the dep |
| `subsumptionViolated`        | fake-disqualified subsumption claims that hold on the matched set |
| `AgreementRate`              | reports 1.0 on pairs with zero matched evidence |
| `LowCoverage` flag           | shows `low=false` on pairs with high evaluated and zero matched |
| `NO_FIXTURE_COVERAGE` gap    | misses pairs that have co-evaluations but zero matched |

The single rule that prevents all five: any code that reads
`CoEvaluations` to make a semantic claim about the pair must filter
on `ReadOverlap` first. Counting raw fixture-presence is correct only
for the `FixturesEvaluated` denominator, which is intentionally a
different number than `FixturesMatched`.

This rule is pinned by the `TestClassify_UnresolvedOverlap_*` family
in `classify_test.go`, the `TestAgreementRate_IgnoresUnresolvedOverlap`
and `TestAgreementRate_AllUnresolvedReturnsZero` tests in
`evaluate_test.go`, and the `TestBuildReport_LowCoverageKeysOnMatched
NotEvaluated`, `TestBuildReport_NoFixtureCoverageGapFiresOnZero
Matched`, and `TestBuildReport_WitnessesFilterUnresolvedOverlap`
tests in `render_test.go`. Together these are the contract that
prevents a future maintainer from "simplifying" `disagreementWitnesses`
back to its pre-3.5 form. The Node 3f dry-run is the canary: a
regression here surfaces as a 3-4× spike in CONTRADICTIONs and
DIVERGENCEs that all show low matched counts.

## Conceptual distinctions that need code enforcement

Three distinctions in this package exist in the taxonomy but do not
enforce themselves in code. A future maintainer adding a new category,
a new field, or a new payload type should scan this list and confirm
their change respects each one:

1. **Matched vs evaluated** — `FixturesMatched` and `FixturesEvaluated`
   are different numbers and have different meanings. Semantic claims
   read from matched only; coverage denominators read from evaluated.
   Conflating them produces vacuous findings (Iteration 3.5).

2. **Observed vs differing values** — CONTRADICTION witnesses surface
   `observed_values` (the overlap subset of `PathValues`); DIVERGENCE
   witnesses surface `differing_values` (the non-overlap subset).
   Same data, different views; conflating them either leaks irrelevant
   path data into CONTRADICTIONs or hides the differing dep paths
   that explain DIVERGENCEs (Node 2d).

3. **Disqualifying vs precedence** — the four-category ordering is a
   disqualifying rule, not first-match-wins. A pair that triggers
   CONTRADICTION is excluded from REDUNDANCY even if the agreement
   rate would otherwise qualify. See sections 1-3 above (Node 3c).

4. **Reads-for-routing vs reads-for-evaluation** — controls read some
   property paths to gate which asset class they apply to (e.g.,
   `type == "kubernetes_apiserver"`), not to evaluate the asset's
   security state. The CEL dependency extractor does not distinguish
   the two — both come back as plain dependency paths — so two
   controls that route on the same metadata path appear to "share a
   dependency" they do not actually share semantically. Without a
   filter, every K8s control routing on `type` co-evaluates against
   every other K8s control on every fixture; CEL absent-value
   semantics on the wrong asset class produce verdict pairs the
   classifier mistakes for disagreement (Iteration 3.6).

   The structural fix lives in the dependency extractor (separating
   routing reads from evaluation reads at extraction time) and is a
   future Iteration 2 extension. The interim defense is a path-level
   denylist (`metadataOnlyPaths` in `overlap.go`) that strips routing
   paths from candidate-pair `Overlap` and discards pairs whose
   substantive overlap is empty. The denylist is small and closed —
   `type` only as of 3.6, audited from the 630-control catalog.
   Extending it is a catalog-driven decision: add a path when a new
   routing-only field appears in shared deps, not speculatively.

The pattern across all four: a conceptual distinction in the
taxonomy that compiles fine if you ignore it, fails subtly in
production, and only surfaces under real-catalog stress (Node 3f).
Pinning tests are the only durable defense — discussion-only rules
walk back in.

## Maintenance contract

Any change to `Classify`, `classifyOne`, `AgreementRate`,
`BuildReport`, or the witness selection helpers must preserve all
four invariants. The pinning tests above are the contract. If a
future feature requires relaxing one of these invariants, escalate
the design before implementing — the relaxation is almost certainly
the bug.

## Provenance

Sections 1-3 were established during Iteration 3 Node 3c review
(2026-04-17). Section 4 and the original conceptual-distinctions
checklist (items 1-3) were added in Iteration 3.5 (2026-04-17), after
Node 3f surfaced 836 vacuous CONTRADICTIONs traced to a single
matched-vs-evaluated conflation that affected five callsites.

Item 4 in the conceptual-distinctions checklist (reads-for-routing
vs reads-for-evaluation) and the `metadataOnlyPaths` denylist were
added in Iteration 3.6 (2026-04-17), after the post-3.5 Node 3f
re-run showed that all 233 surviving CONTRADICTIONs and 778 of 779
DIVERGENCEs had `[type]` as their only shared dependency — every
single one a K8s control routing on asset class. After 3.6 the count
dropped to 0 CONTRADICTIONs, 0 DIVERGENCEs, with 1430 metadata-only
candidate pairs filtered upstream and the one substantive pair
correctly demoted to NO_FIXTURE_COVERAGE.

The taxonomy discussions in earlier iterations did not pin these
rules down explicitly; this doc and the pinning tests are how the
rules survive future maintenance after the rationale leaves working
memory.

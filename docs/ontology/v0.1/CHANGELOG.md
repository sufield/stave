# Ontology Changelog

## v0.1.4 — unreleased (draft)

Coverage-honesty additions to the ConflictReport schema. The previous draft assumed silent coverage was tolerable; this revision surfaces it explicitly so downstream consumers cannot mistake "no conflict reported" for "control was actually analyzed."

- **Added `analysis_gaps[]`** (required at top level) — explicit list of controls excluded from analysis, with `reason` enum: `ALIASED_PREDICATE` (static extraction unsupported — see v0.1.2 extractor note), `NO_FIXTURE_COVERAGE` (no matching fixtures in corpus), `EXTRACTION_FAILED` (extractor error on a non-aliased predicate). Required because absent gaps are the most common failure mode of coverage-style reports: the empty array must be present and intentional, not assumed.
- **Added `low_coverage` flag to `corpus_coverage`** — boolean signal set when `fixtures_evaluated < 5`. Per-pair confidence diagnostic: a pair surviving overlap analysis but evaluated against fewer than five fixtures is a candidate for additional fixture authoring before the conflict is acted on.
- **Why ship this in 0.1.4 and not later** — the surfaced alias gap (six S3 ACL/auth controls) sits on top of the highest CONTRADICTION-likelihood territory in the catalog. Deferring would publish a report whose silence on that surface area is misleading.

## v0.1.3 — unreleased (draft)

Conflict detection primitive. Schema-only in this release; detection
implementation and CLI wiring follow in subsequent nodes of Iteration 3.

- **Added Primitive 6: ConflictReport** — schema at `v0.1/conflict-report.schema.json`. Pairs of controls in one of four relationships: `CONTRADICTION`, `REDUNDANCY`, `EMPIRICAL_SUBSUMPTION`, `DIVERGENCE`.
- **Common superstructure** — single `pairs[]` with `category` enum and category-specific `payload`. Chosen over four per-category arrays so cross-category queries (e.g., "all conflicts involving CTL.X") are one filter and future category additions do not silently break downstream iterators.
- **Discriminator via `if/then`** — payload shape is constrained by `category` so validation errors point at the actual field mismatch rather than `failed to match any of 4 schemas`.
- **Corpus coverage per pair** — every pair carries `corpus_coverage` (fixtures_evaluated, fixtures_matched, corpus_version). Confidence is surfaced honestly, not implied.
- **Witness selection rule** — `CONTRADICTION.disagreement_witnesses` and `DIVERGENCE.minimal_disagreement_fixtures` capped at 5, selected lexicographically by (fixture_path, asset_id), with `witnesses_truncated` flag. Deterministic by construction.
- **CONTRADICTION subcategories** — `LOGIC_BUG` vs `MISSING_ASSET_CLASS_GUARD` to distinguish predicate logic defects from authoring defects (the fix differs).
- **REDUNDANCY overlap dimensions** — requires agreement on dependencies, verdicts, compliance mappings, attack_stage, and remediation. Compliance and remediation are hashed rather than inlined so the report references catalog content instead of duplicating it.
- **Renamed `SUBSUMPTION` → `EMPIRICAL_SUBSUMPTION`** — honest naming: the relationship holds against the current fixture corpus, not in the general case. Static subsumption proof is undecidable and out of scope.
- **CLI exit codes live on the command, not the schema** — the schema is data; exit-code policy belongs to `stave verify catalog` (documented separately). This lets library consumers of the schema set their own CI policy.
- **Fixture corpus** — existing Stave fixtures (stave/ goldens plus aws-lab/, gcp-lab/, dns-lab/). Pinned to `fixture_corpus_version` (git SHA) in every report for reproducibility.
- **Witness observed_values and differing_values — kept distinct by intent.** The two fields answer different diagnostic questions and must not be merged back into a single field for "consistency." CONTRADICTION asks *"when A and B saw the same values, why did they disagree?"* — the witness records the shared `observed_values` at the overlap paths, because that shared state is exactly what makes the disagreement a defect. DIVERGENCE asks *"when A and B reached different conclusions, what was different?"* — the witness records `differing_values` at the predicate-boundary paths, because that delta is the likely cause of the divergence. Same Witness data model, different semantic slot; merging them erases the semantic distinction the downstream consumer relies on to interpret the finding. Surfaced when writing the schema test suite: the ad-hoc smoke test in Node 2b let `observed_values` slip through against a schema that did not define it; the committed test in Node 2d forced the gap into the open.
- **Committed schema validation suite** — `internal/ontology/schema_test.go` exercises the schema on six cases: meta-validation (the schema itself compiles as JSON Schema 2020-12), one positive case per category (payload shape per discriminator branch), a mismatched-payload negative case (confirms error path points at `payload`), an unknown-category rejection (closed enum), a missing-required-field rejection (`report_id`), and an additional-property rejection (closed root). Framing the five primitives as authoritative and the ConflictReport as a *derived artifact* (not Primitive 6) is reflected in `README.md`.

## v0.1.2 — 2026-04-17

Reasoning fields added to PostureFinding.

- **Added `reasoning` block** (required) — predicate_id, dependencies, observed_values, missing_paths, evaluation_ms. Deterministic evaluation context sufficient to reproduce the verdict.
- **Added `triggers` block** (optional) — prior_snapshot_id, changed_paths, prior_values, prior_verdict, verdict_delta, anomaly. Populated in multi-snapshot contexts for property-change attribution.
- **Added static dependency extractor** — `internal/cel/deps/` extracts property paths from control predicates. 99% catalog coverage (624/630). 7 unit tests.
  - **Alias expansion: not yet supported.** Aliased predicates (the remaining 6/630 controls — predominantly S3 ACL/auth) cannot be statically analyzed and are returned with `ErrAliasedPredicate`. Downstream consumers (see ConflictReport v0.1.4) must surface these in `analysis_gaps[]` with reason `ALIASED_PREDICATE` rather than treating them as zero-conflict controls. Lifting this limitation requires resolving the alias to its concrete CEL form and re-running extraction; tracked as a follow-up against the extractor, not a defect in the coverage number.
- **Added Python example** — `docs/examples/python/query_triggers.py` demonstrates downstream trigger querying.

## v0.1.1 — 2026-04-17

Contract lock iteration. Closes four gaps.

- **Added Primitive 5: Exemption** — governance decision to suppress findings, with scope matching, compensating controls, and expiry
- **Added `status` field to PostureFinding** — lifecycle state (ACTIVE, SUPPRESSED, RESOLVED) independent of verdict; maps to ocsf:status_id
- **Added `suppression` and `suppression_history`** to PostureFinding for audit trail continuity
- **Corrected verdict enum** — reduced to VIOLATION, PASS, INCOMPLETE; INCOMPLETE carries required `incomplete_reason`
- **Specified finding_id hash** — SHA-256 of (control_id, asset_id) only; stable across schema evolution
- **Specified state machine** — ACTIVE, SUPPRESSED, RESOLVED transitions with regression path
- **Deprecated `excepted_findings[]` and `acknowledged_findings[]`** — removal at 1.0
- **Added freeze criteria** — five conditions for 0.1.x to 1.0.0

## v0.1.0 — 2026-04-17

Initial draft. Four primitives defined:

- **Asset** — configuration state of a cloud resource at a point in time
- **Control** — executable safety property (CEL predicate) with compliance metadata
- **CompoundRisk** — N co-failing controls with blast radius multiplier
- **PostureFinding** — evaluation result extending OCSF Compliance Finding

Taxonomies: Severity, Verdict, SensitivityTier, AttackStage, Capability vocabulary.

Foundation layers adopted without modification: OSCAL 1.1.2, OCSF 1.5.0, STIX 2.1, MITRE ATT&CK v15.

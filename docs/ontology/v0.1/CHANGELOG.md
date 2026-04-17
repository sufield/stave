# Ontology Changelog

## v0.1.3 / v0.1.4 — withdrawn

The ConflictReport schema introduced in 0.1.3 and extended in 0.1.4 has been withdrawn along with the conflict-detection package. Catalog authoring assistance is not part of the Stave core; see [`docs/design-notes/catalog-authoring-as-service.md`](../../design-notes/catalog-authoring-as-service.md) for the decision and the data that informed it. The ontology version returns to 0.1.2.

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

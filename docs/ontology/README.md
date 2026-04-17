# Stave Ontology

**Version:** 0.1.4 (draft — ConflictReport schema with analysis_gaps + low_coverage; detection implementation in progress)
**Status:** Draft — battle-tested by CLI commands, not yet frozen

This document defines the semantic foundation for the Stave platform. It is the developer contract for Stave Apps.

## Design Principle

Reuse existing ontologies where they fit. Extend only where they do not. Never replace what already has community adoption.

## Foundation Layers (reused without modification)

### Layer 1: OSCAL (NIST) — Control and Compliance

Stave uses [OSCAL](https://pages.nist.gov/OSCAL/) for:

- Control catalog (catalog.json)
- Compliance profiles (profile.json)
- Assessment results (assessment-results.json)
- Plan of Action and Milestones (poam.json)

Stave controls map to OSCAL controls by control-id. Stave compliance citations map to OSCAL control references. `stave export oscal` produces OSCAL 1.1.2 conformant documents.

| OSCAL Concept | Stave Equivalent |
|---|---|
| oscal:Control | Control (1:1 mapping) |
| oscal:Profile | ComplianceProfile |
| oscal:Finding | PostureFinding (for export) |
| oscal:AssessmentResult | Assessment (for export) |

### Layer 2: OCSF (Linux Foundation) — Finding Output

Stave uses [OCSF](https://schema.ocsf.io/) Compliance Finding (class_uid: 2003) for SIEM-consumable finding output. `stave export ocsf` maps Stave findings to OCSF Compliance Finding events.

| OCSF Concept | Stave Equivalent |
|---|---|
| ocsf:ComplianceFinding | PostureFinding (for export) |
| ocsf:severity_id | Severity (mapped) |
| ocsf:status_id | Status (mapped: ACTIVE=1, SUPPRESSED=3, RESOLVED=4) |
| ocsf:resource | Asset reference |

### Layer 3: STIX 2.1 (OASIS) — Threat Intelligence Context

Stave uses [STIX](https://oasis-open.github.io/cti-documentation/) vocabulary for attack pattern taxonomy.

| STIX Concept | Stave Equivalent |
|---|---|
| stix:AttackPattern | AttackStage (MITRE ATT&CK) |
| stix:CourseOfAction | RemediationAction |
| stix:Vulnerability | CVE reference (via inventory) |
| stix:KillChainPhase | attack_stage taxonomy |

### Layer 4: MITRE ATT&CK — Tactic/Technique Taxonomy

Stave maps every control to an [ATT&CK](https://attack.mitre.org/) tactic. The `attack_stage` field in every control and finding uses ATT&CK tactic IDs (TA0001-TA0043).

## Stave Extension Layer

The five primitives that no existing ontology covers. These are the novel concepts that define Stave's domain.

### Primitive 1: Asset Observation

The configuration state of a cloud resource at a point in time. This is what `obs.v0.1.json` captures. No existing ontology models infrastructure configuration properties as typed, versioned, snapshot-able state.

Schema: [`v0.1/asset.schema.json`](v0.1/asset.schema.json)

### Primitive 2: Control

A named, versioned, executable safety property that must always hold true across the entire system. Unlike a prescriptive policy control (a requirement statement), a Stave control contains an executable CEL predicate that deterministically evaluates whether the property holds against any asset that composes the system. Maps to oscal:Control for compliance reporting.

Schema: [`v0.1/control.schema.json`](v0.1/control.schema.json)

### Primitive 3: Compound Risk (Chain)

N controls co-failing on related assets produces a compound finding with elevated severity and blast radius multiplier. Called "chain" in the CLI. Closest STIX concept is AttackPattern but chains model co-failing configuration controls, not adversary behavior descriptions.

Schema: [`v0.1/compound-risk.schema.json`](v0.1/compound-risk.schema.json)

### Primitive 4: Posture Finding

The result of evaluating a Control against an Asset. Extends OCSF Compliance Finding (class_uid 2003) with lifecycle status, suppression tracking, and temporal posture context.

A PostureFinding separates two independent dimensions: **verdict** (what the CEL predicate determined) and **status** (the finding's lifecycle state). A SUPPRESSED finding still has a real verdict (typically VIOLATION) — suppression does not erase the evaluation outcome.

Schema: [`v0.1/posture-finding.schema.json`](v0.1/posture-finding.schema.json)

#### finding_id Specification

`finding_id` is a SHA-256 hash of `(control_id, asset_id)`. Exact inputs: the string `"finding:"` concatenated with `control_id`, `":"`, and `asset_id`, hashed with SHA-256, prefix `"sha256:"`, truncated to 16 hex characters.

The hash does **not** include predicate version, observed property values, or assessment timestamp. This makes `finding_id` stable across:
- Schema evolution (extractor improvements, new property fields)
- Predicate version changes (control logic updates)
- Observation timing (same finding detected at different times)

A finding that transitions `RESOLVED → ACTIVE` (regression) reuses the same `finding_id` because the `(control_id, asset_id)` pair is unchanged. This preserves dwell-day history and enables downstream apps to track the full lifecycle of a finding across resolution and recurrence.

#### Reasoning Block

Every PostureFinding carries a required `reasoning` object containing the deterministic evaluation context: which property paths the predicate reads (`dependencies`), what values were observed (`observed_values`), which paths were absent (`missing_paths`), and how long evaluation took (`evaluation_ms`).

The contents of `reasoning` are sufficient to reproduce the verdict given the predicate source and the observation. This is the determinism guarantee downstream apps rely on. A finding with `verdict: VIOLATION` and `reasoning.observed_values: {"properties.storage.access.public_read": true}` tells the consumer exactly why the control fired without heuristics.

PASS findings carry reasoning too — downstream apps need to answer "why is this passing?" not just "why is this failing?"

#### Trigger Attribution

In multi-snapshot contexts (`stave diff`, `stave forensics`), PostureFinding carries an optional `triggers` object that attributes the finding to specific property changes between snapshots. The attribution is deterministic: `changed_paths` is the set intersection of `reasoning.dependencies` with paths that differ between observations. No temporal proximity heuristics.

If the verdict flipped but no dependency path changed, `triggers.anomaly` is set to `PREDICATE_VERSION_CHANGE` (catalog updated between snapshots) or `UNEXPLAINED` (non-determinism bug to investigate).

#### State Machine

```
                 +---> SUPPRESSED ---(exemption expires)---> ACTIVE
                 |         ^                                    |
Finding created -+---> ACTIVE ----(exemption granted)------> SUPPRESSED
                 |         |
                 |         +---(control passes)---> RESOLVED
                 |                                      |
                 |         +---(control fails again)----+
                 |         v
                 +---> ACTIVE (regression, same finding_id)
```

### Primitive 5: Exemption

A time-bounded governance decision to suppress a specific finding or class of findings. An Exemption is not a Control (it does not evaluate a property) and not a PostureFinding (it does not represent an evaluation result). It is a decision layered on top of the evaluation outcome that alters the lifecycle status of one or more PostureFindings from ACTIVE to SUPPRESSED.

When an Exemption expires or is revoked, affected PostureFindings transition back to ACTIVE with their original verdict intact. The suppression period is recorded in `suppression_history[]` on each affected finding, preserving the audit trail. If an Exemption specifies `compensating_controls`, those controls must be PASS for the suppression to remain valid — if any compensating control fails, the Exemption is invalidated and findings revert to ACTIVE.

No existing ontology (OSCAL, OCSF, STIX) models governance exemptions as a first-class primitive. OSCAL has risk responses but not time-bounded, compensating-control-enforced suppressions. This is a Stave extension.

Schema: [`v0.1/exemption.schema.json`](v0.1/exemption.schema.json)

#### Deprecated Fields (removal at 1.0)

The following parallel arrays on the Assessment output are deprecated in favor of the `status` and `suppression` fields on PostureFinding:

- `excepted_findings[]` — replaced by findings with `status: SUPPRESSED`
- `acknowledged_findings[]` — replaced by findings with `status: SUPPRESSED` and `suppression` block

These arrays remain in 0.1.x for backward compatibility. Consumers should migrate to reading `findings[]` and filtering on `status`. Both arrays will be removed at 1.0.

## Relationships

```
Asset --evaluated by--> Control --produces--> PostureFinding
  |                                                |
  +--sensitivity--> SensitivityTier --amplifies--> | severity
                                                   |
PostureFinding --participates in--> CompoundRisk --+--> ChainFinding
  |                                                |
  +--status: SUPPRESSED--> Exemption               |
  |    (suppression block references Exemption)     |
  +--status: RESOLVED--> (finding no longer active) |
                                                    |
PostureFinding --cited by--> ComplianceProfile (OSCAL)
                                                    |
PostureFinding --maps to--> OCSF ComplianceFinding (2003)
  |  verdict  --> ocsf finding content
  |  status   --> ocsf status_id
                                                    |
CompoundRisk --maps to--> STIX AttackPattern        |
Control.remediation --maps to--> STIX CourseOfAction|
Control.attack_stage --maps to--> MITRE ATT&CK Tactic
```

## Derived Artifacts

Derived artifacts are data structures produced by operating on the five primitives — not primitives themselves. A downstream app developer reading this ontology should understand the primitives deeply (they are the domain vocabulary) and consume derived artifacts opportunistically (they are the outputs of specific commands). Derived artifacts live in their own schema files and evolve independently of primitive schemas.

### Conflict Report

A ConflictReport is the output of catalog conflict detection. It describes relationships between Controls in the catalog — not the state of any Asset and not the result of any evaluation against an Asset. It is how catalog authors and downstream apps ask: *"are the controls in this catalog internally coherent?"*

Schema: [`v0.1/conflict-report.schema.json`](v0.1/conflict-report.schema.json)

ConflictReport is explicitly not a primitive. The five primitives (Asset, Control, CompoundRisk, PostureFinding, Exemption) define the domain; a ConflictReport reports on one of them (Control) in aggregate. No existing ontology (OSCAL, OCSF, STIX) describes relationships between controls as a first-class data structure — OSCAL profiles compose controls but do not detect semantic conflict between them. The data shape is a Stave extension; the category of artifact (a report about the catalog) is where this differs from the primitives above.

#### The four categories

- **CONTRADICTION** — shared dependencies, opposing verdicts on the same observation. Correctness defect. Two subcategories: `LOGIC_BUG` (one predicate is genuinely wrong) and `MISSING_ASSET_CLASS_GUARD` (both predicates encode valid but different interpretations; the fix is adding a guard, not repairing logic).
- **REDUNDANCY** — identical behavior across every overlap dimension: dependencies, verdicts on every fixture, compliance mappings, attack_stage, and remediation. Hygiene issue. Agreement on any single dimension is insufficient — the full set is required to avoid false positives against intentionally separated controls.
- **EMPIRICAL_SUBSUMPTION** — one control's dependency set is a strict subset of the other's, and its VIOLATIONs imply the broader control's VIOLATIONs across the current corpus. Informational, empirical only. Not a proof of subsumption in general — the name makes the limitation explicit.
- **DIVERGENCE** — overlapping dependencies with verdict agreement below 100%. Informational, opt-in (not surfaced by default — it is the normal state for layered controls at different severities). Each divergence carries up to 5 witness fixtures and the differing property values so catalog authors can see the boundary.

#### Shape: common superstructure

Every pair is an element of a single `pairs[]` array, discriminated by `category`. Category-specific fields live in `payload`. This shape was chosen over per-category arrays because it keeps cross-category queries (*"all conflicts involving CTL.X"*) to a single filter and because adding a future category extends an enum rather than silently breaking downstream iterators that hard-coded the known array names.

#### Corpus coverage, made explicit

Every pair carries `corpus_coverage` with `fixtures_evaluated`, `fixtures_matched`, and `corpus_version` (the git SHA of the fixture tree). The quality of conflict detection depends directly on corpus coverage; the report surfaces that dependency rather than hiding it. A REDUNDANCY pair with `fixtures_matched: 0` is vacuous and should be treated with caution.

Authors adding a new control are expected to add at least one fixture that exercises it against each existing control with overlapping dependencies. This contract sits between the catalog and the fixture corpus and is part of the ontology, not a CLI convention.

#### Exit codes are not in the schema

The ConflictReport schema describes the data. Exit-code policy — which categories block CI — belongs to the producing CLI command (`stave verify catalog`), documented separately. This lets library consumers of the schema (Python apps, custom CI) apply their own policy rather than inheriting the CLI's.

## Freeze Criteria

The following must be true before 0.1.x advances to 1.0.0:

1. **External validation.** At least one app built against the 0.1 schema without requiring ontology changes to function.
2. **Schema validation suite.** Each `.schema.json` file ships with a test suite that validates conformant and non-conformant documents.
3. **No open correctness defects.** No known issue where the schema permits semantically invalid states (e.g., `status: SUPPRESSED` without a `suppression` block, or `verdict: INCOMPLETE` without `incomplete_reason`).
4. **Deprecated field migration path.** The 0.1.x deprecation of `excepted_findings[]` and `acknowledged_findings[]` has been in place for at least two minor versions, giving consumers a migration window.
5. **finding_id stability proven.** The hash algorithm has been exercised across at least 90 days of production assessment runs without requiring a change.

## Contract Stability Guarantee

| Version | Guarantee |
|---|---|
| 0.1.x | Draft, may have additive changes |
| 1.0.x | Stable, additive-only within major version |
| 2.0.x | Breaking change, migration path required |

**Additive changes** (allowed within major version): new properties on existing types, new enum values on open enumerations, new optional fields.

**Breaking changes** (require major version bump): removing or renaming required fields, changing a field's type, changing enum values on closed enumerations, changing the finding_id hash algorithm.

JSON consumers that ignore unknown fields will not break on additive changes.

## Developer Notes

A Stave App developer needs to read:

1. **This ontology** — understand concepts, relationships, taxonomies
2. **obs.v0.1.json** — understand what extractors produce
3. **out.v0.1.json** — understand what `stave apply` produces

No SDK. No API. No runtime dependency on Stave. An app reads `out.v0.1.json` and reasons about it using the concepts defined here. The ontology is the integration layer. The JSON files are the data. Stave is the engine that produces the data. Apps consume the data.

The ontology guarantees that `finding_id`, `dwell_days`, `verdict`, `status`, `severity`, and `remediation.changes` will always be present, always mean the same thing, and will not be renamed or removed in a minor version.

## Machine-Readable Files

| File | Contents |
|---|---|
| [`v0.1/asset.schema.json`](v0.1/asset.schema.json) | Asset Observation JSON Schema |
| [`v0.1/control.schema.json`](v0.1/control.schema.json) | Control JSON Schema |
| [`v0.1/compound-risk.schema.json`](v0.1/compound-risk.schema.json) | Compound Risk JSON Schema |
| [`v0.1/posture-finding.schema.json`](v0.1/posture-finding.schema.json) | Posture Finding JSON Schema |
| [`v0.1/exemption.schema.json`](v0.1/exemption.schema.json) | Exemption JSON Schema |
| [`v0.1/taxonomies.json`](v0.1/taxonomies.json) | Severity, Verdict, Status, IncompleteReason, Sensitivity, AttackStage, Capability enums |
| `mapping.json` | Concept-to-standard mapping table |
| `extensions.json` | JSON Schema for Stave extensions |
| `attack-stages.json` | ATT&CK tactic ID mapping |
| `resource-classes.json` | Resource class taxonomy |

## References

| Ontology | Version | URL |
|---|---|---|
| OSCAL | 1.1.2 | https://pages.nist.gov/OSCAL/ |
| OCSF | 1.5.0 | https://schema.ocsf.io/ |
| STIX | 2.1 | https://oasis-open.github.io/cti-documentation/ |
| ATT&CK | v15 | https://attack.mitre.org/ |

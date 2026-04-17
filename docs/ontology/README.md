# Stave Ontology

**Version:** 0.1.0
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
| ocsf:status_id | Verdict (mapped) |
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

The four primitives that no existing ontology covers. These are the novel concepts that define Stave's domain.

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

The result of evaluating a Control against an Asset. Extends OCSF Compliance Finding (class_uid 2003) with Stave-specific temporal and contextual properties.

Schema: [`v0.1/posture-finding.schema.json`](v0.1/posture-finding.schema.json)

## Relationships

```
Asset --evaluated by--> Control --produces--> PostureFinding
  |                                                    |
  +--sensitivity--> SensitivityTier --amplifies--> severity
                                                       |
PostureFinding --participates in--> CompoundRisk --fires--> ChainFinding
                                                       |
PostureFinding --suppressed by--> Exemption            |
                                                       |
PostureFinding --cited by--> ComplianceProfile (OSCAL) |
                                                       |
PostureFinding --maps to--> OCSF ComplianceFinding (2003)
                                                       |
CompoundRisk --maps to--> STIX AttackPattern           |
                                                       |
Control.remediation --maps to--> STIX CourseOfAction   |
                                                       |
Control.attack_stage --maps to--> MITRE ATT&CK Tactic
```

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

The ontology guarantees that `finding_id`, `dwell_days`, `verdict`, `severity`, and `remediation.changes` will always be present, always mean the same thing, and will not be renamed or removed in a minor version.

## Machine-Readable Files

| File | Contents |
|---|---|
| [`v0.1/asset.schema.json`](v0.1/asset.schema.json) | Asset Observation JSON Schema |
| [`v0.1/control.schema.json`](v0.1/control.schema.json) | Control JSON Schema |
| [`v0.1/compound-risk.schema.json`](v0.1/compound-risk.schema.json) | Compound Risk JSON Schema |
| [`v0.1/posture-finding.schema.json`](v0.1/posture-finding.schema.json) | Posture Finding JSON Schema |
| [`v0.1/taxonomies.json`](v0.1/taxonomies.json) | Severity, Verdict, Sensitivity, AttackStage, Capability enums |
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

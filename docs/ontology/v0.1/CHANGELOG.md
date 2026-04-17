# Ontology Changelog

## v0.1.0 — 2026-04-17

Initial draft. Four primitives defined:

- **Asset** — configuration state of a cloud resource at a point in time
- **Control** — executable safety property (CEL predicate) with compliance metadata
- **CompoundRisk** — N co-failing controls with blast radius multiplier
- **PostureFinding** — evaluation result extending OCSF Compliance Finding

Taxonomies: Severity, Verdict, SensitivityTier, AttackStage, Capability vocabulary.

Foundation layers adopted without modification: OSCAL 1.1.2, OCSF 1.5.0, STIX 2.1, MITRE ATT&CK v15.

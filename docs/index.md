# Stave Documentation

## Getting Started

- [Start Here](start-here.md) — First steps with Stave
- [Time to First Finding](time-to-first-finding.md) — Get your first result quickly
- [S3 Assessment Workflow](s3-assessment.md) — End-to-end S3 security assessment
- [Recipes](recipes.md) — Common usage patterns and examples

## Concepts

- [FAQ](faq.md) — Terminology, approach, and how Stave differs from existing tools
- [Design Philosophy](design-philosophy.md) — Why Stave works the way it does
- [System Controls as Code](system-invariant-as-code.md) — Controls-based safety evaluation
- [Evaluation Semantics](evaluation-semantics.md) — How findings are produced
- [Evaluation Engine Capabilities](evaluation-engine-capabilities.md) — Predicate operators and matching
- [Observation Contract](observation-contract.md) — Observation data requirements
- [Contract-First Schemas](contracts.md) — Schema-driven design
- [Scope and Support](scope-and-support.md) — What Stave covers

## User Guide

- [User Documentation](user-docs.md) — Complete user reference
- [Authoring Controls](controls/authoring.md) — Write custom controls
- [Sanitization](sanitization.md) — Scrubbing sensitive data from output
- [Offline and Air-Gapped Operation](offline-airgapped.md) — Running without network access

## Schemas

- [Control Schema (ctrl.v1)](schema/ctrl.v1.md)
- [Observation Schema (obs.v0.1)](schema/obs.v0.1.md)
- [Output Schema (out.v0.1)](schema/out.v0.1.md)
- [Diagnose Schema (diagnose.v1)](schema/diagnose.v1.md)

## Architecture

- [Architecture Overview](architecture/overview.md)

## Security and Trust

- [Security and Trust](trust/01-security-and-trust.md) — Security model overview
- [Security Guarantees](trust/01-guarantees.md) — What Stave guarantees
- [Execution Safety](trust/execution-safety.md) — Runtime safety properties
- [Data Flow and I/O](trust/data-flow-and-io.md) — What data goes where
- [Threat Model](security/threat-model.md)
- [Minimum IAM for S3 Ingest](security/iam-minimum-s3-ingest.md)

## Release and Verification

- [Release Security](trust/02-release-security.md) — How releases are built and signed
- [Verify a Release](trust/verify-release.md) — Step-by-step verification guide
## Project

- [Stability and Versioning](project/stability.md)
- [Scope and Limits](project/limits.md)

## Testing

- [Coverage Policy](testing/coverage-policy.md)

## Contributing

- [CLI Style Guide](cli-style-guide.md)
- [Operator Contract](contrib/operator-contract.md) — Verification commands for contributors
- [Bug Reproduction Guide](contrib/bug-repro-guide.md)
- [Bug Reproduction Template](contrib/bug-repro-template.md)
- [Bug Template](bug-template.md)

## Reports

- [Documentation QC Report](reports/docs-qc.md)

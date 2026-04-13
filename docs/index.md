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
- [Risk Reasoning Engine](risk-reasoning.md) — Compound risk scoring, safety chains, attack stages, exposure ranking
- [Blast Radius](blast-radius.md) — Scope-aware multipliers, detection blindness, interpreting output
- [Identity Blast Radius](identity-blast-radius.md) — Credential compromise reach, assume chains, extractor patterns
- [Unauthenticated Reachability](unauthenticated-reachability.md) — Anonymous access path detection, composition attacks, extractor BFS
- [Data Exfiltration](data-exfiltration.md) — Reverse reachability: how data gets out
- [Drift Detection](drift-detection.md) — Configuration drift as a violation, baseline comparison
- [Security Chronology](bisect-timeline.md) — Binary search for violation onset, violation window discovery, Patient Zero forensics
- [Supply Chain Ingress](supply-chain-ingress.md) — OIDC federation trust analysis, CI/CD ingress risks
- [Secret Blast Radius](secret-blast-radius.md) — Secret-to-data lateral movement, credential blast radius
- [Recovery Isolation](recovery-isolation.md) — Decoupled recovery, anti-ransomware SPoF detection
- [Data Sovereignty](data-sovereignty.md) — Cross-border access detection, jurisdictional compliance
- [Shadow Logic Detection](shadow-logic.md) — NotAction/NotResource bypass, negative logic analysis
- [KMS Concentration Risk](kms-concentration.md) — Cryptographic single point of failure detection
- [Vendor Trust Leash](vendor-trust-leash.md) — Third-party SaaS access hygiene, ghost access detection
- [Evidence Bundling](evidence-bundling.md) — Signed portable evidence for air-gap GRC integration
- [Multi-Profile Evaluation](multi-profile.md) — Compliance compression, per-framework readiness, remediation ROI
- [Remediation Ranking](remediation-ranking.md) — Prioritized roadmap, SLA urgency, remediation bundles
- [Evaluation Engine Capabilities](evaluation-engine-capabilities.md) — Predicate operators and matching
- [Observation Contract](observation-contract.md) — Observation data requirements
- [Contract-First Schemas](contracts.md) — Schema-driven design
- [Scope and Support](scope-and-support.md) — What Stave covers

## User Guide

- [User Documentation](user-docs.md) — Complete user reference
- [Authoring Controls](controls/authoring.md) — Write custom controls
- [Building an Extractor](extractor-prompt.md) — Steampipe, CloudQuery, AWS Config, or custom
- [Reachability Extractor Guide](extractor-reachability.md) — BFS graph traversal, boundary detection, completeness tracking
- [Exfiltration Extractor Guide](extractor-exfiltration.md) — Reverse reachability, egress detection, wildcard write analysis
- [Cross-Env Extractor Guide](extractor-cross-env.md) — Transitive trust traversal across accounts
- [Escalation Extractor Guide](extractor-escalation.md) — Multi-step privilege escalation chain analysis
- [Supply Chain Extractor Guide](extractor-supply-chain.md) — OIDC trust policy analysis
- [Pre-Commit Hook](integrations/pre-commit.md) — Block unsafe configs before commit
- [Atlantis Post-Plan](integrations/atlantis.md) — Evaluate Terraform plans before apply
- [OPA Rego Export](integrations/opa-export.md) — Export controls to OPA/Conftest Rego format
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
- [Minimum IAM for S3 Observation Collection](security/iam-minimum-s3-observation.md)

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

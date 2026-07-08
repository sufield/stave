# Stave Documentation

## Getting Started

- [Start Here](start-here.md) — First steps with Stave
- [Time to First Finding](https://www.systeminvariant.dev/docs/tutorials/first-finding) — Get your first result quickly
- [S3 Assessment Workflow](https://www.systeminvariant.dev/docs/how-to/s3-assessment) — End-to-end S3 security assessment
- [Recipes](https://www.systeminvariant.dev/docs/how-to/recipes) — Common usage patterns and examples

## Concepts

- [FAQ](faq.md) — Terminology, approach, and how Stave differs from existing tools
- [Design Philosophy](https://www.systeminvariant.dev/docs/explanation/design-philosophy) — Why Stave works the way it does
- [System Invariant as Code](https://www.systeminvariant.dev/docs/explanation/system-invariant-as-code) — invariant-based safety evaluation
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
- [Entitlement Entropy](entitlement-entropy.md) — Shadow admin detection, privilege creep, permission category mixing
- [KMS Concentration Risk](kms-concentration.md) — Cryptographic single point of failure detection
- [Vendor Trust Leash](vendor-trust-leash.md) — Third-party SaaS access hygiene, ghost access detection
- [Telemetry Bridge](telemetry-bridge.md) — NDJSON telemetry for dashboards, SIEM, and compliance trending
- [Evidence Bundling](evidence-bundling.md) — Signed portable evidence for air-gap GRC integration
- [Multi-Profile Evaluation](multi-profile.md) — Compliance compression, per-framework readiness, remediation ROI
- [Observation Contract](contract/README.md) — Observation data requirements
- [Contract-First Schemas](https://www.systeminvariant.dev/docs/reference/contracts) — Schema-driven design
- [Scope and Support](scope-and-support.md) — What Stave covers

## User Guide

- [User Documentation](user-docs.md) — Complete user reference
- [Authoring Controls](https://www.systeminvariant.dev/docs/how-to/control-authoring) — Write custom controls
- [Building an Extractor](extractor-prompt.md) — Steampipe, CloudQuery, AWS Config, or custom
- [Reachability Extractor Guide](extractor-reachability.md) — BFS graph traversal, boundary detection, completeness tracking
- [Exfiltration Extractor Guide](extractor-exfiltration.md) — Reverse reachability, egress detection, wildcard write analysis
- [Cross-Env Extractor Guide](extractor-cross-env.md) — Transitive trust traversal across accounts
- [Escalation Extractor Guide](extractor-escalation.md) — Multi-step privilege escalation chain analysis
- [Supply Chain Extractor Guide](extractor-supply-chain.md) — OIDC trust policy analysis
- [Pre-Commit Hook](integrations/pre-commit.md) — Block unsafe configs before commit
- [Atlantis Post-Plan](https://www.systeminvariant.dev/docs/how-to/atlantis-integration) — Evaluate Terraform plans before apply
- [Sanitization](https://www.systeminvariant.dev/docs/how-to/sanitization) — Scrubbing sensitive data from output
- [Offline and Air-Gapped Operation](https://www.systeminvariant.dev/docs/explanation/offline-airgapped) — Running without network access

## Schemas

- [Control Schema (ctrl.v1)](https://www.systeminvariant.dev/docs/reference/schema-ctrl)
- [Observation Schema (obs.v0.1)](https://www.systeminvariant.dev/docs/reference/schema-obs)
- [Output Schema (out.v0.1)](https://www.systeminvariant.dev/docs/reference/schema-out)
- [Diagnose Schema (diagnose.v1)](https://www.systeminvariant.dev/docs/reference/schema-diagnose)

## Architecture

- [Architecture Overview](architecture/overview.md)

## Security and Trust

- [Security and Trust](https://www.systeminvariant.dev/docs/explanation/trust-and-security) — Security model overview
- [Security Guarantees](https://www.systeminvariant.dev/docs/explanation/guarantees) — What Stave guarantees
- [Execution Safety](https://www.systeminvariant.dev/docs/explanation/execution-safety) — Runtime safety properties
- [Data Flow and I/O](https://www.systeminvariant.dev/docs/explanation/data-flow) — What data goes where
- [Threat Model](https://www.systeminvariant.dev/docs/explanation/threat-model)
- [Minimum IAM for S3 Observation Collection](security/iam-minimum-s3-observation.md)

## Release and Verification

- [Release Security](trust/02-release-security.md) — How releases are built and signed
- [Verify a Release](trust/verify-release.md) — Step-by-step verification guide
## Project

- [Stability and Versioning](https://www.systeminvariant.dev/docs/reference/stability)
- [Scope and Limits](https://www.systeminvariant.dev/docs/reference/limits)

## Testing

- [Coverage Policy](testing/coverage-policy.md)

## Contributing

- [CLI Style Guide](cli-style-guide.md)
- [Operator Contract](https://www.systeminvariant.dev/docs/reference/operator-contract) — Verification commands for contributors
- [Bug Reproduction Guide](https://www.systeminvariant.dev/docs/how-to/bug-reports)
- [Bug Reproduction Template](contrib/bug-repro-template.md)
- [Bug Template](bug-template.md)

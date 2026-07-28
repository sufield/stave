# Stave Documentation

## Get Started

Step-by-step from zero to first evaluation.

- [Install](../README.md#install) — Go install, build from source, or Codespace
- [First evaluation](getting-started/first-evaluation.md) — run against demo fixtures
- [Import your snapshots](getting-started/import-snapshots.md) — AWS Config, Steampipe, or aws+jq collector
- [CI integration](getting-started/ci-integration.md) — GitHub Actions, GitLab CI, SARIF upload
- [Onboarding skills](../_skills/README.md) — six guided walkthroughs for AI coding agents

## Reference

What Stave checks and what it outputs.

- [Control catalog](controls/reference.md) — controls by service (generated)
- [Chain catalog](../chains/README.md) — compound attack chains by family
- [Command reference](command-reference.md) — every command and flag (generated)
- [Schemas](../schemas/README.md) — JSON Schema definitions for all data formats
- [Compliance frameworks](reference/compliance-frameworks.md) — NIST, CIS, FFIEC, ISO 27001, OWASP NHI, CSA
- [Output formats](reference/output-formats.md) — JSON, SARIF, text, JSONL, exit codes
- [Observation contract](contract/README.md) — required fields per asset type
- [Remediation output](remediation/README.md) — machine-readable property changes
- [Collector IAM policy](trust/collector-policy.md) — read-only IAM policy with SMT proof
- [Steampipe mappings](../contracts/steampipe/README.md) — Steampipe column → obs.v0.1 field maps

## How-To

Task-oriented guides.

- [Use assessment templates](how-to/use-templates.md) — pick a template, run an assessment
- [Use compliance lenses](how-to/use-compliance.md) — HIPAA, SOC2, PCI-DSS, NIST mapping
- [Use packs](how-to/use-packs.md) — scoped control bundles (IAM, GuardDuty, FedRAMP, …)
- [Evaluate exploitability](how-to/evaluate-exploitability.md) — compound chains and severity tiers
- [Generate evidence packets](how-to/evidence-packet.md) — tamper-evident bundles for auditors
- [Integrate with other tools](../integrations/README.md) — Terraform, Steampipe, AWS Config, Slack, pre-commit
- [Write a control](how-to/write-a-control.md) — contributing to the catalog

## Explanation

How and why things work.

- [Architecture](architecture/overview.md) — the evaluation pipeline (snapshot → CEL → findings)
- [Compound chains](explanation/compound-chains.md) — how chain rules compose findings
- [Exploitability model](explanation/exploitability.md) — the three-tier classification
- [Snapshot model](explanation/snapshot-model.md) — why snapshots, not live APIs
- [Evaluation semantics](evaluation-semantics.md) — how predicates, thresholds, and duration work
- [Ontology](ontology/README.md) — attack stages, resource classes, domain taxonomy
- [Reasoning engines](../reasoning-specs/README.md) — Z3, Soufflé, Clingo, Prolog specs
- [Snapshot capture](transform/capture.md) — how to capture cloud state

## Compliance Coverage

Framework-specific mapping with control counts.

- [HIPAA](hipaa.md)
- [NIST 800-53](nist-800-53/README.md)
- [NIST CSF 2.0](nist-csf-2/README.md)
- [ISO 27001](iso27001/README.md)
- [FFIEC](ffiec/README.md)
- [CSA CCM](csa-coverage.md)
- [OWASP NHI Top 10](compliance/owasp-nhi-top10.md)

## Security & Trust

- [Collector policy](trust/collector-policy.md) — IAM policy audit + SMT proof
- [Release security](trust/02-release-security.md) — build provenance and verification
- [Verify a release](trust/verify-release.md)

## Examples

114 self-contained scenarios with vulnerable + remediated fixtures.

- [Examples index](../examples/README.md) — browse by attack pattern
- [Examples catalog](../examples/CATALOG.md) — full matrix with engine results

## For Contributors

- [Architecture](ARCHITECTURE.md) — layer map, dependency rule, command trace
- [Contributing](CONTRIBUTING.md) — setup, workflow, PR guidelines
- [Development](DEVELOPMENT.md) — build, test, lint
- [Doctrine](DOCTRINE.md) — design principles
- [Glossary](GLOSSARY.md) — term definitions
- [CLI style guide](cli-style-guide.md) — output conventions
- [Community scripts](../contrib/README.md) — Atlantis, hooks
- [Control definitions](../controls/README.md) — 97 service directories
- [Coverage audits](audits/) — ATT&CK, IAM, S3, Lambda coverage reports
- [Tool comparison](comparison/aws-compliance-mod.md) — Stave vs Steampipe compliance mod

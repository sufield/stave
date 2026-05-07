# Stave

Stave is a static analysis tool that performs model checking over cloud infrastructure configurations — verifying system invariants via predicate evaluation (CEL) and formal verification (Z3/cvc5/Yices) against air-gapped snapshots, with no cloud credentials required.

[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave?v=1)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)

## What is Stave?

Stave is a static analysis tool that performs model checking over cloud infrastructure configurations. It takes observation snapshots representing infrastructure state and verifies safety properties (system invariants) expressed as predicates over that model.

The verification core is designed for soundness: a passing verdict constitutes a proof of safety within the bounds of the provided model and invariant catalog. When a violation is detected, the solver produces a constructive counterexample — the specific principal, action, and resource tuple that demonstrates the failure.

The system performs three classes of verification:

- **Property checking** — evaluates concrete predicates against concrete state via [CEL](https://github.com/google/cel-go). A decidable problem answered in linear time.
- **Compound safety verification** — evaluates whether co-occurring failures across multiple resources constitute a reachable attack path. A graph reachability problem.
- **Configuration compatibility verification** — via external SMT solvers (Z3, cvc5, Yices), determines whether multiple policy documents are jointly satisfiable. Produces mathematical proofs or counterexamples.

## Reasoning engines

Six reasoning engines consume the same fact export, each answering a different kind of question:

| Engine | Question |
|---|---|
| **CEL** | Does this snapshot violate this rule? |
| **Z3 / cvc5 / Yices** | Can an unsafe state exist? (satisfiability proof) |
| **Soufflé** | What is the full blast radius? (reachability enumeration) |
| **Clingo** | What configurations violate constraints? (violation enumeration) |
| **PySAT** | Which control combinations are unsafe? (boolean regression) |
| **Prolog** | Why is this path reachable? (proof tree derivation) |

See [`examples/`](examples/) for runnable harnesses per engine and the [`compare-engines/`](examples/compare-engines/) cross-engine consensus harness that surfaces blind spots when engines disagree.

## Operating model

Stave operates on static snapshots with no cloud credentials, no network access, and no runtime instrumentation — fully air-gapped by design. Findings are deterministic, traceable, and inspectable: same inputs produce the same outputs, every conclusion carries the evidence chain that derived it, and every step is reviewable end-to-end.

## Features

- **2590 built-in controls across 74 domains** — S3, IAM, VPC, EC2, RDS, Lambda, ECS, ECR, EKS, CloudTrail, CloudWatch, KMS, OpenSearch, Redshift, Neptune, DocumentDB, Glue, CodeBuild, SageMaker, Bedrock, Cognito, API Gateway, EMR, Kinesis, MSK, EFS, Route53, DMS, SSM, ACM, WAF, Shield, Network Firewall, EventBridge, Config, Backup, and [38 more](docs/controls/reference.md)
- **23 ghost reference controls** — cross-inventory reasoning detects dangling references to deleted resources across IAM policies, resource policies, event triggers, compute dependencies, network infrastructure, cross-account trust, and temporal confirmation. Detection no per-resource scanner can perform.
- **30+ compound chain definitions** — detect multi-step attack paths across data protection, identity, detection, recovery, sovereignty, supply chain, cryptographic concentration, WAF safety envelope, ghost resource exfiltration, and silent monitoring collapse
- **7-control WAF safety envelope** — presence, enforcement, OWASP coverage, logging, origin lockdown, parser overflow protection, evasion observability
- **Full OWASP Top 10 coverage** — all categories at Full across P1 and P2 priorities
- **15/15 ATT&CK cloud technique coverage** — configuration preconditions for 100% of AWS ATT&CK techniques tested by Atomic Red Team
- **20/21 Rhino Security Labs escalation techniques** — 26 ESCALATE controls covering privilege escalation preconditions (1 remaining is AWS-deprecated)
- **10 compliance profiles** — HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0
- **Risk reasoning engine** — compound risk scoring across co-failing controls, MITRE-aligned attack stage summary, blast radius multipliers
- **Full triage output per finding** — DEFECT (what's wrong), INFECTION (how it enables attack), FAILURE (worst case), OBSERVED (what the engine consulted), DELTA (mechanically verified fix)
- **Remediation ranking** — `stave rank` produces a prioritized remediation roadmap with SLA urgency, risk impact percentages, and remediation bundles
- **Drift detection** — `stave drift` compares two snapshots and treats configuration changes as violations, exit code 3 for CI/CD gating
- **Continuous monitoring** — `stave watch` monitors observation directories for new snapshots, detects regressions in real time, emits alerts to stdout or JSONL file sinks
- **Unsafe duration tracking** — detects how long assets remain misconfigured across snapshots
- **Graph export** — `stave path` and `stave graph export` emit nodes and edges in JSON, DOT, CSV, JSON-LD, and GraphML for graph-data-science workloads (centrality, community detection, shortest path, influence propagation) on any library — Neo4j GDS, igraph, NetworkX, Spark GraphX, Gephi
- **Custom controls** — YAML with `unsafe_predicate` for any asset type, no code changes
- **Evidence bundling** — `stave bundle` produces signed, portable evidence archives for air-gap GRC integration (ASFF compatible)
- **CI/CD ready** — exit codes, SARIF output, baseline tracking, policy gating
- **Extensible by design** — new properties and controls are additive and backward-compatible

## Install

```bash
brew tap sufield/tap && brew install stave
```

Or build from source:

```bash
git clone https://github.com/sufield/stave.git
cd stave && make build
```

## Quick start

```bash
# Initialize project with built-in S3 controls
stave init --profile aws-s3

# Place observation snapshots in observations/
# (at least two snapshots for duration-based controls)

# Validate inputs
stave validate

# Evaluate and produce findings
stave apply --format json

# Investigate unexpected results
stave diagnose
```

## How it works

```
Extract → Validate → Apply → Act

1. Extract    Capture asset configs as obs.v0.1 JSON (extractor is external)
2. Validate   Check inputs are well-formed and complete
3. Apply      Evaluate snapshots against safety controls, produce findings
4. Act        Review findings, remediate, re-evaluate
```

Stave evaluates observations. Extractors are separate programs (any language) that produce `obs.v0.1` JSON from cloud APIs, Terraform state, or any config source. See [Building an Extractor](docs/extractor-prompt.md).

## Usage examples

### Standard evaluation

```bash
stave apply --format json > evaluation.json
```

### Compliance profiles

```bash
stave apply --profile hipaa --input observations.json --include-all --format json
stave apply --profile cis-aws-v3.0 --input observations.json --include-all --format json
stave apply --profile soc2 --input observations.json --include-all --format json
stave apply --profile pci-dss-v4.0 --input observations.json --include-all --format json
# Also: nist-800-53, fedramp, gdpr, ffiec, iso-27001, nist-csf-2.0
```

### CI/CD gating

```bash
stave ci baseline save
stave apply --format json | stave ci gate --fail-on new
```

### SARIF for GitHub Security

```bash
stave apply --format sarif > results.sarif
```

## Extensibility

Add new detection capabilities without engine changes:

1. **Extract** — write an extractor that outputs `obs.v0.1` JSON
2. **Author** — write a YAML control with `unsafe_predicate`
3. **Evaluate** — `stave apply --controls ./my-controls`

New observation properties are additive and backward-compatible. Existing controls ignore new fields. New controls check them. This is how the Access Grants, MRAP, and CloudFront OAC controls were added — zero Go changes, 6 YAML files, 6 test fixtures.

## Built-in controls

2590 controls across 74 domains:

### AWS S3 (112 controls)

| Category | Count | What they detect |
|----------|:---:|-----------------|
| `public` | 18 | Public read/write/list, website hosting, prefix exposure, CloudFront bypass |
| `acl` | 4 | ACL escalation, reconnaissance, FULL_CONTROL grants |
| `access` | 14 | Cross-account, wildcard actions, presigned URLs, Access Grants, policy disclosure |
| `encrypt` | 6 | Missing encryption at rest/in transit, KMS for PHI |
| `network` | 11 | VPC/IP conditions, VPC endpoint policy, Multi-Region Access Point PAB |
| `versioning` | 3 | Disabled versioning, missing MFA delete |
| `lock` | 4 | Object lock mode, retention period |
| `logging` | 10 | Access logging, CloudTrail object-level audit |
| `lifecycle` | 2 | Lifecycle rules, PHI retention |
| `governance` | 4 | Data classification tags |
| `write_scope` | 2 | Upload scope, content type restriction |
| `tenant` | 1 | Prefix-based tenant isolation |
| `takeover` | 2 | Dangling bucket references, CDN origins |
| `artifacts` | 1 | VCS artifacts on public buckets |
| `cors` | 1 | Wildcard origin CORS on non-public-by-design buckets |
| `misc` | 8 | Incomplete data, completeness checks |

### AWS IAM (164 controls)

Root account MFA and access keys, console user MFA, credential rotation, password policy, privilege escalation (self-modify, PassRole, AssumeRole), permissions boundaries, break-glass persistence, cross-environment access, inactive accounts, blast-radius thresholds for roles and users. CIS AWS Benchmark aligned.

### AWS OpenSearch (132 controls)

Authentication enforcement, VPC deployment, fine-grained access control, encryption at rest and node-to-node, HTTPS, Kibana exposure, access policy wildcards, audit logging, snapshot encryption. Prevents the Darkbeam (3.8B records), Wyze, and Microsoft Elasticsearch breach patterns.

### GCP Cloud Storage (7 controls)

Public access, uniform bucket-level access, CMEK encryption, access logging, object versioning, data completeness. CIS GCP Benchmark aligned.

### DNS (3 controls)

Vendor-agnostic dangling DNS reference detection — subdomain takeover, storage bucket takeover, supply chain takeover via software distribution endpoints. Works with any DNS provider.

Full reference: [Control reference](docs/controls/reference.md)

## Documentation

| | |
|---|---|
| [Quickstart](docs/time-to-first-finding.md) | Get your first finding in 5 minutes |
| [Building an extractor](docs/extractor-prompt.md) | Steampipe, CloudQuery, AWS Config, or custom |
| [Authoring controls](docs/controls/authoring.md) | Write custom YAML controls |
| [Pre-commit hook](docs/integrations/pre-commit.md) | Block unsafe configs before commit |
| [Atlantis integration](docs/integrations/atlantis.md) | Evaluate Terraform plans before apply |
| [Risk reasoning](docs/risk-reasoning.md) | Compound risk scoring and safety chains |
| [Identity blast radius](docs/identity-blast-radius.md) | Credential compromise reach analysis |
| [Unauthenticated reachability](docs/unauthenticated-reachability.md) | Anonymous access path detection |
| [Data exfiltration](docs/data-exfiltration.md) | Reverse reachability: how data gets out |
| [Drift detection](docs/drift-detection.md) | Configuration drift as violation |
| [Evidence bundling](docs/evidence-bundling.md) | Signed portable evidence for GRC |
| [Remediation ranking](docs/remediation-ranking.md) | Prioritized remediation roadmap |
| [Evaluation semantics](docs/evaluation-semantics.md) | How duration tracking works |
| [Architecture](docs/architecture/overview.md) | System design overview |
| [FAQ](docs/faq.md) | Common questions |
| [Full docs index](docs/index.md) | Everything else |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

## License

[Apache License 2.0](LICENSE)

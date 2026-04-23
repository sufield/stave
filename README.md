# Stave

A deterministic cloud security intelligence engine. Evaluates invariants against local infrastructure snapshots to produce compound attack path analysis, compliance evidence packages, and identity-centric risk rankings — air-gapped, traceable, no cloud credentials required.

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave?v=1)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)

## What is Stave?

Stave detects compound attack paths in cloud infrastructure by evaluating invariants against local snapshots — no cloud credentials, no live API calls. It produces compliance evidence packages, SLA-tracked remediation guidance, identity blast radius rankings, and a standards-based security graph exportable to Neo4j, SIEM platforms, and GRC tools. The same snapshot that detects misconfigurations produces HIPAA audit evidence, MITRE ATT&CK-annotated findings, and OCSF-compliant graph exports

## Why this exists

Scanners produce disconnected lists: "this bucket is public, that key is unrotated, logging is disabled." The auditor must reason about how they combine. Stave automates that reasoning.

### Example: what reasoning looks like

A scanner reports three independent findings:

```
[high]     CTL.S3.PUBLIC.001   — bucket is publicly readable
[high]     CTL.S3.ENCRYPT.001  — bucket is not encrypted
[medium]   CTL.S3.LOG.001      — access logging is disabled
```

Three items in a list. The analyst must figure out which matter.

Stave sees the same three findings, then reasons:

```
[CRITICAL] Chain: public_phi_exposure
  This bucket holds PHI (sensitivity: 3.0x), is publicly readable
  (exposure: 2.0x), is unencrypted, and has no audit trail.

  Safety envelope: COLLAPSED (3 of 4 layers failed)
  Compound score:  150.0
  Fix any of:      CTL.CLOUDTRAIL.DATAREAD.001
  Attack stages:   initial_access, exfiltration, detection_evasion
```

Same data. Different output. The scanner says "three things are wrong." Stave says "the safety envelope around PHI data has collapsed — this is a total exposure with no audit trail, and enabling CloudTrail would be the cheapest fix to start restoring the envelope."

Every score is a **deterministic, traceable reasoning chain**. Compound scores show their full factor breakdown (severity x duration x blast radius x exposure). Chain findings list which controls failed and which fixes break the chain. Given the same inputs, the same ranking is always produced — every step auditable, every conclusion reproducible. Define safety controls in YAML, compile them to [CEL](https://github.com/google/cel-go), evaluate JSON snapshots locally. Any vendor, any asset type, air-gapped by design.

## Features

- **1187 built-in controls across 72 domains** — S3, IAM, VPC, EC2, RDS, Lambda, ECS, ECR, EKS, CloudTrail, CloudWatch, KMS, OpenSearch, Redshift, Neptune, DocumentDB, Glue, CodeBuild, SageMaker, Bedrock, Cognito, API Gateway, EMR, Kinesis, MSK, EFS, Route53, DMS, SSM, ACM, WAF, Shield, Network Firewall, EventBridge, Config, Backup, and [36 more](docs/controls/reference.md)
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
- **Graph export** — `stave path` exports nodes and edges in JSON, DOT, and CSV for Neo4j GDS centrality analysis, choke point identification, and effective permission reasoning
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

1187 controls across 72 domains:

### AWS S3 (100 controls)

| Category | Count | What they detect |
|----------|:---:|-----------------|
| `public` | 17 | Public read/write/list, website hosting, prefix exposure, CloudFront bypass |
| `acl` | 4 | ACL escalation, reconnaissance, FULL_CONTROL grants |
| `access` | 13 | Cross-account, wildcard actions, presigned URLs, Access Grants, policy disclosure |
| `encrypt` | 4 | Missing encryption at rest/in transit, KMS for PHI |
| `network` | 11 | VPC/IP conditions, VPC endpoint policy, Multi-Region Access Point PAB |
| `versioning` | 3 | Disabled versioning, missing MFA delete |
| `lock` | 3 | Object lock mode, retention period |
| `logging` | 10 | Access logging, CloudTrail object-level audit |
| `lifecycle` | 2 | Lifecycle rules, PHI retention |
| `governance` | 4 | Data classification tags |
| `write_scope` | 2 | Upload scope, content type restriction |
| `tenant` | 1 | Prefix-based tenant isolation |
| `takeover` | 2 | Dangling bucket references, CDN origins |
| `artifacts` | 1 | VCS artifacts on public buckets |
| `cors` | 1 | Wildcard origin CORS on non-public-by-design buckets |
| `misc` | 8 | Incomplete data, completeness checks |

### AWS IAM (106 controls)

Root account MFA and access keys, console user MFA, credential rotation, password policy, privilege escalation (self-modify, PassRole, AssumeRole), permissions boundaries, break-glass persistence, cross-environment access, inactive accounts, blast-radius thresholds for roles and users. CIS AWS Benchmark aligned.

### AWS OpenSearch (13 controls)

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
| [OPA Rego export](docs/integrations/opa-export.md) | Export controls to OPA/Conftest |
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

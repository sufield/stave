# Stave

Deterministic, traceable risk reasoning engine for cloud infrastructure. Evaluates the structural integrity of your safety envelope using local snapshots — no cloud credentials required.

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave?v=1)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)

## What is Stave?

Stave is not a scanner, not a CSPM, and not an IaC linter. It is a new category: a **safety envelope evaluator** that applies formal safety engineering principles to cloud infrastructure.

**Unit of analysis:** Control × Asset → Safety Envelope. Each control defines one layer of protection. Each asset has a safety envelope — the complete set of controls protecting it. Stave evaluates individual layers, then reasons about whether the envelope is intact, degraded, or collapsed.

**Output type:** Reasoning Attestation. Not a list of findings. Not a risk score. A structured, deterministic argument about the integrity of each safety envelope — what failed, what the failures mean in combination, and what to fix first to restore the envelope.

This concept comes from safety engineering (IEC 61508, DO-178C) where systems must prove they are safe, not just report what is broken. Stave applies the same discipline to cloud configuration.

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

The output is not a score from an algorithm. It is a **deterministic logical conclusion** from declared invariants — every step traceable, every score reproducible. Define safety controls in YAML, compile them to [CEL](https://github.com/google/cel-go), evaluate JSON snapshots locally. Any vendor, any asset type, air-gapped by design.

## Features

- **253 built-in controls** across 30 domains (S3, IAM, VPC, EC2, RDS, ELB, K8s, CloudTrail, CloudWatch, KMS, and [20 more](docs/controls/reference.md))
- **10 compliance profiles** — HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0
- **Risk reasoning engine** — compound risk scoring across co-failing controls, MITRE-aligned attack stage summary, blast radius multipliers
- **Safety chains** — 4 built-in chain definitions detect compound failures (PHI exposure, root compromise, detection blindness, identity blast radius)
- **Unsafe duration tracking** — detects how long assets remain misconfigured across snapshots
- **Custom controls** — YAML with `unsafe_predicate` for any asset type, no code changes
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

Extraction is out of scope — Stave evaluates observations, it does not fetch data from cloud providers. Extractors are separate programs (any language) that produce `obs.v0.1` JSON. See [Building an Extractor](docs/extractor-prompt.md).

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

253 controls across 30 domains:

### AWS S3 (67 controls)

| Category | Count | What they detect |
|----------|:---:|-----------------|
| `public` | 15 | Public read/write/list, website hosting, prefix exposure, CloudFront bypass |
| `acl` | 4 | ACL escalation, reconnaissance, FULL_CONTROL grants |
| `access` | 9 | Cross-account, wildcard actions, presigned URLs, Access Grants |
| `encrypt` | 4 | Missing encryption at rest/in transit, KMS for PHI |
| `network` | 5 | VPC/IP conditions, VPC endpoint policy, Multi-Region Access Point PAB |
| `versioning` | 3 | Disabled versioning, missing MFA delete |
| `lock` | 3 | Object lock mode, retention period |
| `logging` | 4 | Access logging, CloudTrail object-level audit |
| `lifecycle` | 2 | Lifecycle rules, PHI retention |
| `governance` | 1 | Data classification tags |
| `write_scope` | 2 | Upload scope, content type restriction |
| `tenant` | 1 | Prefix-based tenant isolation |
| `takeover` | 2 | Dangling bucket references, CDN origins |
| `artifacts` | 1 | VCS artifacts on public buckets |
| `misc` | 4 | Incomplete data, completeness checks |

### AWS IAM (44 controls)

Root account MFA and access keys, console user MFA, credential rotation, password policy, privilege escalation (self-modify, PassRole, AssumeRole), permissions boundaries, break-glass persistence, cross-environment access, inactive accounts. CIS AWS Benchmark aligned.

### AWS OpenSearch (12 controls)

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
| [Evaluation semantics](docs/evaluation-semantics.md) | How duration tracking works |
| [Architecture](docs/architecture/overview.md) | System design overview |
| [FAQ](docs/faq.md) | Common questions |
| [Full docs index](docs/index.md) | Everything else |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

## License

[Apache License 2.0](LICENSE)

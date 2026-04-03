# Stave

A configuration safety engine that detects insecure configurations in your cloud environment using only local configuration snapshots — no cloud credentials required.

[Docs](docs/index.md) | [FAQ](docs/faq.md) | [Quickstart](docs/time-to-first-finding.md) | [Demo](DEMO.md) | [Releases](https://github.com/sufield/stave/releases) | [Security](SECURITY.md) | [Contributing](CONTRIBUTING.md)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave?v=1)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)

## Why Stave exists

Cloud security tools fall into two camps: runtime scanners that require credentials and network access, and IaC linters that only see templates before deployment. Neither evaluates actual running configurations offline, tracks how long misconfigurations persist, or lets you define custom safety controls as composable logic.

Stave fills this gap. Controls are YAML-defined using a `ctrl.v1` DSL that compiles to [CEL (Common Expression Language)](https://github.com/google/cel-go) at runtime — giving you a battle-tested expression engine with type safety and deterministic evaluation. Any vendor, any asset type, any JSON property shape. No API calls, no runtime agents, no network access at scan time.

Stave ships three built-in control packs. The **S3 pack** (53 controls) targets the blind spot where existing tools treat Block Public Access as the sole signal for exposure, missing legacy ACL grants, presigned URL abuse, and VPC endpoint policy gaps. The **HIPAA pack** selects the subset of S3 controls required for PHI workloads and maps each to specific HIPAA Security Rule citations (§164.312, §164.316). The **S3 public-exposure pack** provides a focused baseline for public access prevention. The engine is not S3-specific or HIPAA-specific: the same evaluation pipeline, duration tracking, and enforcement artifacts apply to any infrastructure asset you can capture as a JSON snapshot.

## What Stave does

Stave reads point-in-time configuration snapshots and evaluates them against YAML-defined safety controls:

- **CEL-powered evaluation** — `ctrl.v1` predicates compile to [CEL](https://github.com/google/cel-go) programs with operators like `eq`, `ne`, `in`, `missing`, `contains`, `any_match`, and composable `any`/`all` logic
- **Parameterized controls** — controls accept `params` for configurable thresholds (e.g., `params.min_retention_days`) without forking the control definition
- **Any vendor, any asset type** — observations carry a vendor string and asset type; the engine treats all assets uniformly
- **Unsafe duration tracking** — detects how long assets remain misconfigured across multiple snapshots
- **Custom control authoring** — define safety controls in YAML for any asset type without code changes
- **Deterministic output** — same input always produces same findings
- **Enforcement artifacts** — generates fix plans with specific remediation actions
- **Exemptions and exceptions** — exempt entire assets or suppress specific control+asset findings with audit trail and expiry dates
- **53 built-in S3 controls** — covers public exposure, ACL escalation, encryption, versioning, lifecycle, object lock, logging, network restriction, presigned URL abuse, governance, and takeover prevention
- **HIPAA compliance pack** — curated subset of S3 controls mapped to HIPAA Security Rule sections (§164.312, §164.316) with compound risk detection, acknowledged exceptions with compensating controls, and structured compliance reporting
- **CI/CD gating** — exit codes, baseline tracking, policy-based merge blocking, SARIF for GitHub Code Scanning
- **SARIF output** — `--format sarif` for native GitHub Security tab integration

All evaluation runs locally. No cloud credentials. No network access. Air-gapped by design.

## Quick start

### Install

```bash
brew tap sufield/tap && brew install stave
```

Or build from source:

```bash
git clone https://github.com/sufield/stave.git
cd stave && make build
```

### Full workflow

```bash
# 1. Initialize project with built-in S3 controls
stave init --profile aws-s3

# 2. Place observation snapshots (from your extractor) in observations/
#    Stave needs at least two snapshots for duration-based controls.

# 3. Validate inputs
stave validate

# 4. Evaluate and produce findings
stave apply --format json > output/evaluation.json

# 5. Investigate unexpected results
stave diagnose
```

### HIPAA compliance evaluation

```bash
# Evaluate with the HIPAA pack (YAML/CEL controls with duration tracking)
stave apply --profile hipaa --input observations.json --format json

# Compliance profile with compound risk detection and CFR citations
stave evaluate --snapshot observations/snap.json --profile hipaa

# SARIF output for GitHub Code Scanning
stave apply --profile hipaa --input observations.json --format sarif

# List HIPAA pack controls
stave packs show hipaa
```

The `evaluate` command runs 14 Go invariants with compound risk detection
(3 patterns), acknowledged exceptions with compensating controls, and
structured compliance reporting with HIPAA Security Rule citations.

### Run tests

```bash
cd stave && make test
```

### Docker tutorial

44 interactive S3 security scenarios + HIPAA compliance profile — no AWS credentials required:

```bash
docker build -f stave/build/docker/demo/Dockerfile -t stave-tutorials .
docker run --rm stave-tutorials --list
docker run --rm stave-tutorials --scenario 10
docker run --rm stave-tutorials --scenario 10 --fixed
docker run --rm stave-tutorials --hipaa
docker run --rm stave-tutorials --hipaa --fixed
```

The `--hipaa` mode runs 14 Go invariants with compound risk detection
against a PHI bucket, demonstrating the compliance reporting workflow.

See [DEMO.md](DEMO.md) for details.

## How it works

```
Extract → Validate → Apply → Act

1. Extract    Capture asset configs as obs.v0.1 JSON (extractor is external)
2. Validate   Check inputs are well-formed and complete
3. Apply      Evaluate snapshots against safety controls, produce findings
4. Act        Review findings, remediate, re-evaluate
```

**Extraction is out of scope.** Stave's core engine only evaluates observations — it does not fetch or extract data from cloud providers. Extractors are separate programs that produce `obs.v0.1` JSON and can be written in any language (Python, Go, Rust, shell scripts, Terraform plan parsers, etc.). The only requirement is conforming to the [observation contract](docs/observation-contract.md).

See [Building an Extractor](docs/extractor-prompt.md) for a jumpstart template that works with any LLM to generate a working extractor in minutes.

Snapshots must conform to the [observation contract](docs/observation-contract.md). You need at least two snapshots (two points in time) for Stave to calculate unsafe duration windows.

## Extensibility

The core engine is vendor-neutral and asset-type-agnostic. To evaluate a new asset type:

1. **Extract** — write an extractor in any language that outputs JSON conforming to `obs.v0.1` (any vendor, any asset type, arbitrary JSON properties)
2. **Author controls** — write YAML controls using the `ctrl.v1` schema with predicates over your asset's property paths
3. **Evaluate** — `stave apply --observations ./my-snapshots` (with built-in packs or `--controls ./my-controls` for your own custom controls)

No code changes to Stave required. The `ctrl.v1` predicates compile to CEL expressions that resolve dot-notation field paths against arbitrary JSON, so `properties.encryption.at_rest.enabled eq false` works whether the asset is an S3 bucket, a GCP Cloud Storage bucket, or Azure Blob Storage.

### Backward-compatible schema extension

Adding new detection capabilities does not require engine changes. The `obs.v0.1` observation schema accepts arbitrary JSON properties — new fields are additive and backward-compatible:

- **New properties**: An extractor adds `properties.storage.access_grants.has_broad_write_grant` to its output. Existing controls ignore it. New controls check it.
- **New controls**: A YAML file with an `unsafe_predicate` referencing the new property. Registered in the pack index. No Go code.
- **No breaking changes**: Observations without the new property simply don't trigger the new control (the `eq` operator on a missing field evaluates to false for `unsafe_state` controls).

This is how the 6 most recent controls (Access Grants, Multi-Region Access Points, CloudFront OAC) were added — zero Go changes, 6 YAML files, 6 test fixtures.

## How Stave compares

| Category | Analogy | Examples |
|----------|---------|----------|
| CSPM | Runtime cloud scanner | AWS Config, Wiz, Prisma, Prowler |
| IaC policy | Template linter | OPA, Checkov, tfsec |
| S3 auditors | Exposure enumerator | ScoutSuite, s3audit, CloudMapper |
| System Invariant as Code | Safety evaluator | **Stave** |

| Feature | CSPM | IaC Policy | S3 Auditors | **Stave** |
|---------|:---:|:---:|:---:|:---:|
| No credentials needed | - | Yes | - | Yes |
| Offline snapshots | - | - | - | Yes |
| Deterministic | - | Yes | - | Yes |
| Duration aware | - | - | - | Yes |
| Enforcement | Partial | - | - | Yes |

## Security model

- **Zero network access** — evaluation never contacts external services
- **No credentials** — works on exported snapshots, not live APIs
- **Deterministic output** — `--now` flag pins evaluation time for reproducibility
- **Output sanitization** — `--sanitize` scrubs asset identifiers from findings
- **Signed releases** — SHA256 checksums signed with Sigstore cosign
- **Build provenance** — GitHub-native SLSA attestation on release archives
- **SBOM** — SPDX Software Bill of Materials attached to every release

Details: [Security and Trust](docs/trust/01-security-and-trust.md) | [Threat Model](docs/security/threat-model.md) | [Verify a Release](docs/trust/verify-release.md)

## Built-in controls

Stave ships 53 S3 controls across 15 categories. The HIPAA compliance pack selects the controls required for PHI workloads and maps each to HIPAA Security Rule citations. Custom controls for any asset type can be authored in the same YAML format.

| Category | Controls | What they detect |
|----------|:---:|-----------------|
| `public` | 15 | Public read, write, list via policy, ACL, website hosting, prefix exposure, CloudFront OAI/OAC bypass |
| `acl` | 3 | ACL escalation (WRITE_ACP), reconnaissance (READ_ACP), FULL_CONTROL grants |
| `access` | 8 | Cross-account access, wildcard actions, external write, authenticated-users access, presigned URL restriction, S3 Access Grants scope |
| `encrypt` | 4 | Missing encryption at rest, in transit, KMS requirements for PHI |
| `versioning` | 2 | Disabled versioning, missing MFA delete on backups |
| `lock` | 3 | Missing object lock, wrong mode, insufficient retention for PHI |
| `logging` | 2 | Disabled access logging, missing CloudTrail object-level audit |
| `lifecycle` | 2 | Missing lifecycle rules, PHI retention below HIPAA minimum |
| `network` | 5 | Public-principal policies without IP/VPC conditions, missing VPC endpoint policy, Multi-Region Access Point PAB and policy |
| `governance` | 1 | Missing data-classification tag |
| `write_scope` | 2 | Prefix-wide uploads, unrestricted content types |
| `tenant` | 1 | Missing prefix-based tenant isolation |
| `takeover` | 2 | Dangling bucket references, dangling CDN origins |
| `artifacts` | 1 | VCS artifacts exposed on public buckets |
| `misc` | 2 | Incomplete data preventing safety proof, completeness checks |

Full control reference: [docs/controls/authoring.md](docs/controls/authoring.md)

## CLI commands

### Core workflow

| Command | Purpose |
|---------|---------|
| `init` | Create a starter project layout |
| `validate` | Check inputs are well-formed |
| `apply` | Evaluate controls against observations, produce findings |
| `apply --profile hipaa` | Evaluate using the HIPAA compliance pack |
| `evaluate` | Run compliance profile evaluation with compound risk detection |
| `verify` | Compare before/after evaluations to check remediation |
| `diagnose` | Explain unexpected evaluation results |
| `explain` | Show fields a control requires |

### CI/CD

| Command | Purpose |
|---------|---------|
| `ci baseline` | Save finding baseline for fail-on-new workflows |
| `ci gate` | Enforce CI failure policy |
| `ci fix` | Show machine-readable fix plan for a finding |
| `ci fix-loop` | Run apply-before/apply-after/verify in one command |
| `ci diff` | Compare two evaluations and report new findings |

### Snapshot lifecycle

| Command | Purpose |
|---------|---------|
| `snapshot quality` | Check snapshot quality before evaluation |
| `snapshot plan` | Preview or execute multi-tier retention |
| `snapshot diff` | Compare the latest two observation snapshots |
| `snapshot upcoming` | Upcoming snapshot action items for unsafe assets |
| `snapshot archive` | Archive stale snapshots |
| `snapshot hygiene` | Weekly lifecycle hygiene report |
| `snapshot manifest` | Generate and sign observation integrity manifests |

### Inspection and diagnostics

| Command | Purpose |
|---------|---------|
| `status` | Project state and next steps |
| `trace` | Trace predicate evaluation for a single control against a single asset |
| `inspect` | Low-level security analysis primitives |
| `controls list` | List available controls |
| `packs` | Inspect built-in control packs |
| `doctor` | Check local environment readiness |
| `bug-report` | Collect a sanitized diagnostic bundle for support |

### Other

| Command | Purpose |
|---------|---------|
| `generate` | Generate starter artifacts |
| `report` | Structured findings output |
| `enforce` | Generate enforcement artifacts |
| `config` | Manage project and user configuration |
| `fmt` | Format control and observation files deterministically |
| `lint` | Lint control files for design quality |
| `graph` | Visualize control and asset relationships |
| `security-audit` | Generate enterprise security posture evidence bundle |
| `prompt` | Generate LLM prompts from evaluation results |

```
validate → apply → diagnose
   ↓         ↓        ↓
 Inputs   Findings  Insights
  OK?      Found?    Why?
```

## Concepts

| Term | Definition |
|------|------------|
| **Snapshot** | Point-in-time observation of infrastructure assets (JSON) |
| **Asset** | A single infrastructure component with a vendor, type, and arbitrary JSON properties |
| **Control** | A safety rule assets must satisfy (YAML, `ctrl.v1` schema, compiled to CEL) |
| **Extractor** | An external program (any language) that produces `obs.v0.1` JSON from a data source |
| **Unsafe predicate** | CEL expression that marks an asset as unsafe |
| **Finding** | A detected violation with evidence and remediation guidance |
| **Episode** | A contiguous period where an asset remained unsafe |
| **Max unsafe duration** | Maximum time an asset may remain unsafe before violation |
| **Exemption** | Skips an entire asset from evaluation (by asset ID pattern) |
| **Exception** | Suppresses a specific control+asset finding with reason and expiry date |
| **Compliance pack** | A curated set of controls mapped to a regulatory framework (e.g., HIPAA) |
| **Compound risk** | A dangerous combination of control failures that represents higher risk than any individual finding |
| **Acknowledged exception** | A declared exception with mandatory compensating controls that must all pass |

## Data formats

| Format | Schema | Purpose |
|--------|--------|---------|
| Observations | `obs.v0.1` | Normalized snapshots — flat JSON, one file per timestamp |
| Controls | `ctrl.v1` | Safety rules — YAML with `unsafe_predicate` (compiled to CEL) |
| Output | `out.v0.1` | Findings — JSON with `summary`, `findings`, `excepted_findings`, `remediation_groups` |

Schema references: [ctrl.v1](docs/schema/ctrl.v1.md) | [obs.v0.1](docs/schema/obs.v0.1.md) | [out.v0.1](docs/schema/out.v0.1.md)

## Status

**v0.0.3**

- Engine supports any vendor and asset type
- Built-in control packs: AWS S3 (53 controls), HIPAA compliance, S3 public-exposure baseline
- CEL-powered predicate evaluation with parameterized controls
- HIPAA Security Rule mapping with 14 Go invariants, 3 compound risk detectors, and exception handling
- CI/CD ready: SARIF output, baseline tracking, policy gating, deterministic evaluation
- Custom controls and observations supported for any asset type
- Extractors are external — write in any language, conform to `obs.v0.1`
- 80%+ test coverage (unit + integration testscripts)
- Offline evaluation only

### Schema stability

| Schema | Version | Status |
|--------|---------|--------|
| Observations | `obs.v0.1` | Stable |
| Controls | `ctrl.v1` | Stable |
| Output | `out.v0.1` | Stable |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Security-audit gating failure |
| 2 | Input error |
| 3 | Violations found |
| 4 | Internal error |
| 130 | SIGINT |

## Documentation

- [Start here](docs/start-here.md)
- [Time to first finding](docs/time-to-first-finding.md)
- [Building an extractor](docs/extractor-prompt.md)
- [FAQ](docs/faq.md)
- [Design philosophy](docs/design-philosophy.md)
- [System Invariant as Code](docs/system-invariant-as-code.md)
- [Evaluation semantics](docs/evaluation-semantics.md)
- [Authoring controls](docs/controls/authoring.md)
- [User documentation](docs/user-docs.md)
- [Architecture overview](docs/architecture/overview.md)
- [Full docs index](docs/index.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

- [Bug reproduction guide](docs/contrib/bug-repro-guide.md)
- [Bug template](docs/bug-template.md)
- [CLI style guide](docs/cli-style-guide.md)

## License

[Apache License 2.0](LICENSE)

# Stave

A configuration analysis engine that detects insecure configurations in your cloud environment using only local configuration snapshots — no cloud credentials required.

[Docs](docs/index.md) | [Quickstart](docs/time-to-first-finding.md) | [Releases](https://github.com/sufield/stave/releases) | [Security](SECURITY.md) | [Contributing](CONTRIBUTING.md)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/branch/main/graph/badge.svg)](https://codecov.io/gh/sufield/stave)

## Why Stave exists

Cloud security tools fall into two camps: runtime scanners that require credentials and network access, and IaC linters that only see templates before deployment. Neither evaluates actual running configurations offline, tracks how long misconfigurations persist, or lets you define custom safety invariants as composable logic.

Stave fills this gap. Its evaluation engine operates on arbitrary asset properties using a generic predicate language — any vendor, any asset type, any JSON property shape. Controls are YAML-defined, composable, and evaluated deterministically from local snapshots. No API calls, no runtime agents, no network access at scan time.

The first built-in control pack targets AWS S3 — where existing tools share a blind spot (treating Block Public Access as the sole signal for exposure, missing legacy ACL grants). But the engine is not S3-specific: the same predicate operators, duration tracking, and enforcement pipeline apply to any infrastructure asset you can capture as a JSON snapshot.

## What Stave does

Stave reads point-in-time configuration snapshots and evaluates them against YAML-defined safety controls:

- **Generic predicate engine** — evaluates arbitrary JSON properties using composable `any`/`all` logic with operators like `eq`, `ne`, `in`, `missing`, `contains`, field comparisons, and more
- **Any vendor, any asset type** — observations carry a vendor string and asset type; the engine treats all assets uniformly
- **Unsafe duration tracking** — detects how long assets remain misconfigured across multiple snapshots
- **Custom control authoring** — define safety invariants in YAML for any asset type without code changes
- **Deterministic output** — same input always produces same findings
- **Enforcement artifacts** — generates fix plans with specific remediation actions
- **43 built-in S3 controls** — first control pack covers public exposure, ACL escalation, encryption, versioning, lifecycle, object lock, logging, governance, and takeover prevention

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

### First finding in 60 seconds

```bash
stave demo
cat stave-report.json
```

Expected output:

```
Found 1 violation: CTL.S3.PUBLIC.001
Asset: s3://demo-public-bucket
Evidence: BlockPublicAccess=false, ACL=public-read
Fix: enable account/bucket Block Public Access + deny public principals
```

Compare with a safe configuration:

```bash
stave demo --fixture known-good
```

### Full workflow

```bash
stave init --profile aws-s3
stave validate
stave apply --format json > output/evaluation.json
stave diagnose
```

## How it works

```
Capture → Validate → Apply → Act

1. Capture    Export asset configurations as JSON snapshots
2. Validate   Check inputs are well-formed and complete
3. Apply      Evaluate snapshots against safety controls, produce findings
4. Act        Review findings, remediate, re-evaluate
```

Snapshots must conform to the [observation contract](docs/observation-contract.md). You need at least two snapshots (two points in time) for Stave to calculate unsafe duration windows.

## Extensibility

The core engine is vendor-neutral and asset-type-agnostic. To evaluate a new asset type:

1. **Capture** — export asset configurations as JSON conforming to `obs.v0.1` (any vendor, any asset type, arbitrary JSON properties)
2. **Author controls** — write YAML controls using the `ctrl.v1` schema with predicates over your asset's property paths
3. **Evaluate** — `stave apply --controls ./my-controls --observations ./my-snapshots`

No code changes required. The predicate engine resolves dot-notation field paths against arbitrary JSON, so `properties.encryption.at_rest.enabled eq false` works whether the asset is an S3 bucket, a GCP Cloud Storage bucket, or Azure Blob Storage.

## How Stave compares

| Category | Examples | No credentials needed | Offline snapshots | Deterministic | Duration aware | Enforcement |
|----------|----------|:---:|:---:|:---:|:---:|:---:|
| CSPM | AWS Config, Wiz, Prisma, Prowler | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| IaC policy | OPA, Checkov, tfsec | ✅ | ❌ | ✅ | ❌ | ❌ |
| S3 auditors | ScoutSuite, s3audit, CloudMapper | ❌ | ❌ | ❌ | ❌ | ❌ |
| System Invariant as Code | **Stave** | ✅ | ✅ | ✅ | ✅ | ✅ |

Think of it as:

| Category | Analogy | Example |
|-----------|---------|---------|
| CSPM | Runtime cloud scanner | AWS Config, Wiz |
| IaC policy | Template linter | OPA, Checkov |
| S3 auditor | Exposure enumerator | ScoutSuite |
| System Invariant as Code | Safety evaluator | **Stave** |

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

Stave ships 43 S3 controls across 15 categories as its first control pack. Custom controls for any asset type can be authored in the same YAML format and loaded from any directory (`stave apply --controls /path/to/controls/`).

| Category | Controls | What they detect |
|----------|:---:|-----------------|
| `public` | 13 | Public read, write, list via policy, ACL, website hosting, prefix exposure |
| `acl` | 3 | ACL escalation (WRITE_ACP), reconnaissance (READ_ACP), FULL_CONTROL grants |
| `access` | 5 | Cross-account access, wildcard actions, external write, authenticated-users access |
| `encrypt` | 4 | Missing encryption at rest, in transit, KMS requirements for PHI |
| `versioning` | 2 | Disabled versioning, missing MFA delete on backups |
| `lock` | 3 | Missing object lock, wrong mode, insufficient retention for PHI |
| `logging` | 1 | Disabled access logging |
| `lifecycle` | 2 | Missing lifecycle rules, PHI retention below HIPAA minimum |
| `network` | 1 | Public-principal policies without IP/VPC conditions |
| `governance` | 1 | Missing data-classification tag |
| `write_scope` | 2 | Prefix-wide uploads, unrestricted content types |
| `tenant` | 1 | Missing prefix-based tenant isolation |
| `takeover` | 2 | Dangling bucket references, dangling CDN origins |
| `artifacts` | 1 | VCS artifacts exposed on public buckets |
| `misc` | 2 | Incomplete data preventing safety proof, completeness checks |

Full control reference: [docs/controls/authoring.md](docs/controls/authoring.md)

## CLI commands

| Command | Purpose |
|---------|---------|
| `demo` | First finding in 60 seconds |
| `quickstart` | Auto-detect snapshots and evaluate |
| `status` | Project state and next steps |
| `doctor` | Environment readiness check |
| `init` | Project scaffolding |
| `validate` | Input correctness |
| `plan` | Readiness gate |
| `apply` | Evaluate controls, produce findings |
| `diagnose` | Explain unexpected results |
| `trace` | Clause-level predicate detail |
| `ingest` | Convert AWS snapshots to observations |
| `controls list` | List available controls |
| `explain` | Show fields a control requires |
| `lint` | Control quality checks |
| `snapshot upcoming` | Next snapshot schedule |
| `snapshot prune` | Bounded snapshot retention |
| `snapshot diff` | Drift triage between snapshots |
| `ci baseline` | Save finding baseline |
| `ci gate` | Fail CI on new violations |
| `ci fix-loop` | Verify remediation in CI |

```
validate → plan → apply → diagnose
   ↓         ↓       ↓        ↓
 Inputs    Ready?  Findings  Insights
  OK?               Found?    Why?
                                ↓
                              trace
                           (clause detail)
```

## Concepts

| Term | Definition |
|------|------------|
| **Snapshot** | Point-in-time observation of infrastructure assets (JSON) |
| **Asset** | A single infrastructure component with a vendor, type, and arbitrary JSON properties |
| **Control** | A safety rule assets must satisfy (YAML, `ctrl.v1` schema) |
| **Unsafe predicate** | Conditions that mark an asset as unsafe |
| **Finding** | A detected violation with evidence and remediation guidance |
| **Episode** | A contiguous period where an asset remained unsafe |
| **Max unsafe duration** | Maximum time an asset may remain unsafe before violation |

## Data formats

| Format | Schema | Purpose |
|--------|--------|---------|
| Observations | `obs.v0.1` | Normalized snapshots — flat JSON, one file per timestamp |
| Controls | `ctrl.v1` | Safety rules — YAML with `unsafe_predicate` |
| Output | `out.v0.1` | Findings — JSON with `summary` and `findings` array |

Schema references: [ctrl.v1](docs/schema/ctrl.v1.md) | [obs.v0.1](docs/schema/obs.v0.1.md) | [out.v0.1](docs/schema/out.v0.1.md)

## Status

**v0.0.3**

- Engine supports any vendor and asset type
- Built-in control pack: AWS S3 (43 controls)
- Built-in extraction: AWS S3 (`stave ingest --profile aws-s3`)
- Custom controls and observations supported for any asset type
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
| 2 | Input error |
| 3 | Violations found |
| 4 | Internal error |
| 130 | SIGINT |

## Documentation

- [Start here](docs/start-here.md)
- [Time to first finding](docs/time-to-first-finding.md)
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

# Stave

Offline safety evaluator for cloud configuration snapshots.

[Docs](docs/index.md) | [Quickstart](docs/time-to-first-finding.md) | [Releases](https://github.com/sufield/stave/releases) | [Security](SECURITY.md) | [Contributing](CONTRIBUTING.md)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sufield/stave/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sufield/stave)
[![Go Report Card](https://goreportcard.com/badge/github.com/sufield/stave)](https://goreportcard.com/report/github.com/sufield/stave)
[![codecov](https://codecov.io/gh/sufield/stave/branch/main/graph/badge.svg)](https://codecov.io/gh/sufield/stave)

## Why Stave exists

S3 public exposure persists because existing tools require:

- Cloud credentials to scan
- Network access to query APIs
- Runtime environments that expand attack surface

These constraints prevent consistent, repeatable safety evaluation.

Stave works differently. It evaluates local configuration snapshots against safety controls — offline, deterministic, and credential-free.

## What Stave does

Stave reads point-in-time configuration snapshots and evaluates them against YAML-defined safety controls:

- **43 built-in S3 controls** — public exposure, ACL escalation, encryption, versioning, lifecycle, object lock, logging, governance, takeover prevention
- **Unsafe duration tracking** — detects how long assets remain misconfigured across multiple snapshots
- **Deterministic output** — same input always produces same findings
- **Enforcement artifacts** — generates fix plans with specific remediation actions

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
Capture → Evaluate → Act

1. Capture    Export resource configurations as JSON snapshots
2. Evaluate   Stave reads snapshots + evaluates against safety controls
3. Act        Review findings, remediate, re-evaluate
```

Snapshots must conform to the [observation contract](docs/observation-contract.md). You need at least two snapshots (two points in time) for Stave to calculate unsafe duration windows.

## How Stave compares

| Category | Examples | No credentials needed | Offline snapshots | Deterministic | Duration aware | Enforcement |
|----------|----------|:---:|:---:|:---:|:---:|:---:|
| CSPM | AWS Config, Wiz, Prisma, Prowler | ❌ | ❌ | ❌ | ❌ | ⚠️ |
| IaC policy | OPA, Checkov, tfsec | ✅ | ❌ | ✅ | ❌ | ❌ |
| S3 auditors | ScoutSuite, s3audit, CloudMapper | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Stave** | | ✅ | ✅ | ✅ | ✅ | ✅ |

Think of it as:

| Tool type | Analogy |
|-----------|---------|
| CSPM | Runtime cloud scanner |
| IaC policy | Template linter |
| S3 auditor | Exposure enumerator |
| **Stave** | Snapshot safety evaluator |

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

Stave ships 43 S3 controls across 15 categories:

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
   ↓          ↓          ↓
 Inputs    Findings   Insights
  OK?       Found?    Why?
                        ↓
                      trace
                   (clause detail)
```

## Concepts

| Term | Definition |
|------|------------|
| **Snapshot** | Point-in-time observation of infrastructure assets (JSON) |
| **Asset** | A single infrastructure component (e.g., S3 bucket) with properties |
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

**v0.0.1 (MVP)**

- AWS S3 only
- Configuration snapshots only
- Offline evaluation

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
- [System controls as code](docs/system-invariant-as-code.md)
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

# Stave

Open-source cloud configuration verifier. Proves your AWS
configuration is correct instead of searching for what's wrong —
offline, credential-free.

[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/sufield/stave?quickstart=1)

[Documentation](https://www.systeminvariant.dev/docs) ·
[Tutorial](https://www.systeminvariant.dev/docs/tutorials) ·
[Blog](https://www.systeminvariant.dev/blog) ·
[Metrics](docs/metrics.yaml)

## Install

```bash
go install github.com/sufield/stave/cmd/stave@latest
```

Or build from source:

```bash
git clone https://github.com/sufield/stave.git && cd stave && make build
```

For zero-setup options, click **Open in GitHub Codespaces** above, or see [`stave-workspace/README.md`](stave-workspace/README.md) for Coder workspaces and Docker.

## Quick Start

```bash
# Evaluate a snapshot against the built-in catalog
stave apply --observations ./my-snapshot/

# Discover attack chains across IAM, data, and audit surfaces
stave export-sir --format jsonl --output facts.jsonl
make chain-discover ARGS="-snapshot observations/"

# Try a demo (zero AWS access required)
bash examples/demo-ai-security/run.sh
```

### Onboarding skills (`_skills/`)

Six executable skills guide you from install to real-environment evaluation. Each skill is a markdown file your AI coding agent (Claude Code, Cursor) can read and execute — or you can follow manually.

| # | Skill | Time | AWS needed? |
|---|-------|------|-------------|
| 1 | [_setup](./_skills/_setup/SKILL.md) | 5 min | No |
| 2 | [first-evaluation](./_skills/first-evaluation/SKILL.md) | 10 min | No |
| 3 | [lab-validation](./_skills/lab-validation/SKILL.md) | 30 min | Sandbox ($0) |
| 4 | [write-your-first-control](./_skills/write-your-first-control/SKILL.md) | 20 min | No |
| 5 | [reasoning-engines](./_skills/reasoning-engines/SKILL.md) | 30 min | No |
| 6 | [snapshot-your-account](./_skills/snapshot-your-account/SKILL.md) | 30 min | Yes (read-only) |

## Assessment Templates

Templates are JTBD bundles — everything needed to run a specific
security assessment job. Instead of assembling controls, chains,
and parameters manually, pick a template and go.

```bash
# See which template fits your snapshot
stave recommend --snapshot ./observations/

# Initialize with parameters
stave template init critical-findings --param severity_threshold=high

# Run the assessment
stave apply --values ./stave-values.yaml --snapshot ./observations/
```

### Built-in templates

| Template | Job | Priority |
|----------|-----|----------|
| `critical-findings` | Surface critical/high findings for whatever services are in the snapshot | 10 (default) |
| `independent-audit` | Broad-scope audit across all services | 30 |
| `m-and-a-diligence` | Due-diligence posture snapshot for acquisitions | 50 |
| `breach-reconstruction` | Timeline reconstruction after a security incident | 60 |
| `bucket-hijacking-assessment` | Evaluate router-to-S3 destination bindings for namespace hijacking | 70 |

`critical-findings` is the front door — it always matches and
dynamically selects controls based on which services appear in your
snapshot. No configuration needed; if the catalog has IAM controls
and your snapshot has IAM resources, those controls run. Adding a
new service to the catalog automatically expands coverage.

### Filtered output

When a severity threshold hides findings, eval reports what was
hidden:

```
23 findings at high/critical severity
41 additional findings at medium/low/info severity (hidden)

To include all: set severity_threshold to info in stave-values.yaml
```

### Parameter validation

`stave template init` validates parameter values against allowed
options at init time. Invalid values are rejected immediately:

```
Error: invalid value "super-critical" for parameter severity_threshold
  Allowed values: critical, high, medium, low, info
```

### Custom templates

```bash
# Scaffold a new template
stave template new my-org-assessment

# Edit template.yaml — set controls, chains, recommend_when predicate
# Run and verify
stave template verify my-org-assessment
```

Custom templates in `./stave-templates/` are discovered automatically
alongside built-in templates. `stave template eject` forks a built-in
template for local customization.

## Why not a scanner?

CSPM tools scan for known-bad patterns. Stave verifies that
invariants hold — deterministic, reproducible, mathematically
grounded. The word is *verifier*, not scanner: proof, not heuristics.

Your AI agent has admin access. Your CSPM tool says you're compliant.

![AI Security Demo](docs/talks/ai-security-2026/demo-ai-security.gif)

```bash
bash examples/demo-ai-security/run.sh
```

| | CSPM tools | Cloud configuration verifier |
|---|---|---|
| **Approach** | Search for known-bad patterns | Prove properties hold for all inputs |
| **Scope** | Check individual resources | Compute all paths through the relationship graph |
| **Method** | Sample and alert | Evaluate deterministically with a witness |
| **Access** | Require credentials + runtime access | Operate on an artifact, offline, credential-free |
| **Trust** | Findings you trust on faith | Findings you can independently re-derive |

## Current State

See [`docs/metrics.yaml`](docs/metrics.yaml) for catalog counts,
verification status, and compliance coverage. Generated by
`make metrics`.

## How Controls Are Built

Every control in the catalog traces to a documented security failure —
HackerOne disclosures, public breach postmortems, AWS security
advisories, Mandiant/GTIG incident reports, and offensive tool
prerequisites extracted from Stratus Red Team, Pacu, and CloudFox
source code. Supply-side: exhaustive API surface diffing against
botocore response schemas, cross-cloud transposition from CIS
Azure/GCP benchmarks, and formal policy-semantics analysis grounded
in AWS's own Zelkova research.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

## License

[Apache License 2.0](LICENSE)

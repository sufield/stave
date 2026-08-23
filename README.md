# Stave

Open-source cloud configuration verifier. Proves your AWS
configuration is correct instead of searching for what's wrong. It works
offline without any credentials.

[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/sufield/stave?quickstart=1)

[Documentation](docs/README.md) ·
[Control Reference](docs/controls/reference.md) ·
[Command Reference](docs/command-reference.md) ·
[How-to Guides](docs/how-to/README.md) ·
[Integrations](internal/integrations/README.md)

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

## Snapshots

Stave evaluates local JSON snapshots, not live APIs. Capture once,
evaluate anywhere — offline, deterministic, auditable.

The contract and evaluation are always deterministic. The collection
method is your choice based on your risk posture:

| Profile | Capture path | LLM involved? | Details |
|---|---|---|---|
| Risk-averse / regulated | Bundled collector or pre-built jq filters | No | [Capture guide](docs/transform/capture.md) |
| Pragmatic / local LLMs | LLM maps raw JSON to the contract, then deterministic eval | Local LLM only | [Extractor prompt](docs/extractor-prompt.md) |
| Stave contributors | LLM writes jq filters, team reviews, filters ship in repo | Development tool | [Import methods](docs/getting-started/import-snapshots.md) |

### Quick Start

**1. Capture raw AWS data and transform it:**

```bash
bash scripts/aws-snapshot.sh ./my-snapshot
```

This runs read-only AWS CLI calls (`Get*`, `List*`, `Describe*`),
saves raw JSON to `my-snapshot/raw/`, then calls `stave transform`
to produce `obs.v0.1` observations in `my-snapshot/observations/`.
Requires AWS CLI, jq, and `SecurityAudit` credentials.
[Full IAM policy details →](docs/trust/collector-policy.md)

**2. Evaluate:**

```bash
stave apply --observations ./my-snapshot/observations/
```

**3. Read your findings.**

> **What services are supported?** `stave transform --coverage`
> lists the AWS API shapes with embedded filters.
>
> **What fields does a service need?** `stave contract show --asset-type aws_iam_role`
> shows every property path the catalog reads.
>
> **Why snapshots?** Evaluation never calls AWS APIs. Your security
> data stays local. You can capture from one machine, evaluate on
> another, and diff across time.
> [How the snapshot model works →](docs/explanation/snapshot-model.md)
>
> **All capture methods:** Bundled script, Steampipe, AWS CLI + jq,
> LLM-assisted mapping, or any tool that produces `obs.v0.1` JSON.
> [Import methods →](docs/getting-started/import-snapshots.md)

### Onboarding skills (`internal/_skills/`)

Six executable skills guide you from install to real-environment evaluation. Each skill is a markdown file your AI coding agent (Claude Code, Cursor) can read and execute — or you can follow manually.

| # | Skill | Time | AWS needed? |
|---|-------|------|-------------|
| 1 | [_setup](./internal/_skills/_setup/SKILL.md) | 5 min | No |
| 2 | [first-evaluation](./internal/_skills/first-evaluation/SKILL.md) | 10 min | No |
| 3 | [lab-validation](./internal/_skills/lab-validation/SKILL.md) | 30 min | Sandbox ($0) |
| 4 | [write-your-first-control](./internal/_skills/write-your-first-control/SKILL.md) | 20 min | No |
| 5 | [reasoning-engines](./internal/_skills/reasoning-engines/SKILL.md) | 30 min | No |
| 6 | [snapshot-your-account](./internal/_skills/snapshot-your-account/SKILL.md) | 30 min | Yes (read-only) |

## Assessment Templates

Templates are JTBD bundles — everything needed to run a specific
security assessment job. Instead of assembling controls, chains,
and parameters manually, pick a template and go.

```bash
# Zero arguments — sensible defaults (critical-findings template,
# severity_threshold=high, writes stave-values.yaml)
stave template init

# Run the assessment
stave apply --values ./stave-values.yaml --snapshot ./observations/
```

Arguments are overrides, not requirements:

```bash
# Override the template type
stave template init independent-audit

# Override a parameter
stave template init --param severity_threshold=critical

# See which template fits your snapshot
stave recommend --snapshot ./observations/
```

### Built-in templates

| Template | Job | Priority |
|----------|-----|----------|
| `critical-findings` | Surface critical/high findings for whatever services are in the snapshot | 10 (default) |
| `independent-audit` | Broad-scope audit across all services | 30 |
| `m-and-a-diligence` | Due-diligence posture snapshot for acquisitions | 50 |
| `breach-reconstruction` | Timeline reconstruction after a security incident | 60 |
| `bucket-hijacking-assessment` | Evaluate router-to-S3 destination bindings for namespace hijacking | 70 |

`critical-findings` is the default — zero arguments selects it.
It dynamically selects controls based on which services appear in
your snapshot. No configuration needed; if the catalog has IAM
controls and your snapshot has IAM resources, those controls run.
Adding a new service to the catalog automatically expands coverage.

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

![AI Security Demo](docs/images/demo-ai-security.gif)

```bash
bash examples/demo-ai-security/run.sh
```

A Bedrock agent with broad Lambda invoke + no guardrail + a Lambda tool that reaches a PHI-tagged S3 bucket is the canonical AI compound failure mode: **every component-level check passes**.

- Encryption ✅
- VPC ✅
- Model allowlist ✅
- Public access blocked ✅

**The dashboard is green**. Stave's compound chains compose those individually-passing settings into the attack story they describe — agent → Lambda → S3 PHI, no audit trail.

AI surface coverage spans [Bedrock](internal/controls/bedrock/) (agent, guardrail, model, logging) and [SageMaker](internal/controls/sagemaker/) (training, notebook, pipeline, endpoint) with compound chains across both. Every AI control maps to the OWASP Non-Human Identity (NHI) Top 10 — see [`docs/compliance/owasp-nhi-top10.md`](docs/compliance/owasp-nhi-top10.md).

| | CSPM tools | Cloud configuration verifier |
|---|---|---|
| **Approach** | Search for known-bad patterns | Prove properties hold for all inputs |
| **Scope** | Check individual resources | Compute all paths through the relationship graph |
| **Method** | Sample and alert | Evaluate deterministically with a witness |
| **Access** | Require credentials + runtime access | Operate on an artifact, offline, credential-free |
| **Trust** | Findings you trust on faith | Findings you can independently re-derive |

Stave doesn't replace your scanner. It finds what your scanner structurally cannot — the compound risks that exist in the relationships between individually-correct configurations.

## Catalog at a glance

- **Built-in controls** across S3, IAM, VPC, EC2, RDS, Lambda, ECS, EKS, CloudTrail, KMS, OpenSearch, SageMaker, Bedrock, Cognito, and more.
- **Ghost-reference controls** — cross-inventory detection of pointers to deleted resources (IAM → role, agent → Lambda, CNAME → S3 bucket). Single-resource scanners can't see absence.
- **Compound chain definitions** — multi-step attack paths across identity, data, audit, and recovery surfaces, including AI agent identity (Bedrock + Lambda + S3 PHI, RAG → PHI, notebook → prod role).
- **Compliance profiles** — HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0.

Current counts in [`docs/metrics.yaml`](docs/metrics.yaml).

## How Controls Are Built

Every control in the catalog traces to a documented security failure such as 
HackerOne disclosures, public breach postmortems, AWS security
advisories, Mandiant/GTIG incident reports, and offensive tool
prerequisites extracted from Stratus Red Team, Pacu, and CloudFox
source code. Supply-side: exhaustive API surface diffing against
botocore response schemas, cross-cloud transposition from CIS
Azure/GCP benchmarks, and formal policy-semantics analysis grounded
in AWS's own Zelkova research.

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

## License

[Apache License 2.0](LICENSE)

# Stave

Stave finds dangerous **combinations** in your cloud configuration that single-check scanners miss. A correctly-scoped IAM role, a properly-private S3 bucket, and a correctly-configured Cognito identity pool can compose into a path that lets anonymous users reach patient data. Stave detects these compound risks on static configuration snapshots — no cloud credentials required.

[![codecov](https://codecov.io/gh/sufield/stave/graph/badge.svg?token=OQ72PYGVPZ)](https://codecov.io/gh/sufield/stave)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/sufield/stave?quickstart=1)

## Getting Started

**One-click:** Use the **Open in GitHub Codespaces** badge above — pre-configured; start at Skill 2.

**VS Code / Cursor:** Clone and reopen in the devcontainer (`.devcontainer/`) — start at Skill 2.

**Docker:** `docker run --rm -v ~/snapshot:/data:ro ghcr.io/sufield/stave apply --observations /data/`

**Manual:** See [`_skills/_setup`](./_skills/_setup/SKILL.md), then follow the progression.

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

Devcontainer and Codespaces users skip Skill 1 — the environment is pre-configured.

## What it finds

Your AI agent has admin access. Your scanner says you're compliant.

![AI Security Demo](docs/talks/ai-security-2026/demo-ai-security.gif)

```bash
bash examples/demo-ai-security/run.sh
```

A Bedrock agent with broad Lambda invoke + no guardrail + a Lambda tool that reaches a PHI-tagged S3 bucket is the canonical AI compound failure mode: **every component-level check passes**.

- Encryption ✅
- VPC ✅
- Model allowlist ✅
- Public access blocked ✅

**The dashboard is green**. Stave's compound chains compose those individually-passing settings into the attack story they describe — agent → Lambda → S3 PHI, no audit trail.

The five-act demo above is the 90-second version. The 20-minute conference talk lives at [`docs/talks/ai-security-2026/`](docs/talks/ai-security-2026/) with [slides](docs/talks/ai-security-2026/slides.md), [speaker notes](docs/talks/ai-security-2026/speaker-notes.md), [voiceover script](docs/talks/ai-security-2026/voiceover-script.md), and a [recording runbook](docs/talks/ai-security-2026/RECORDING.md) for the YouTube / dev.to MP4.

| AI surface | Controls | Compound chains |
|---|---:|---|
| [Bedrock agent overprivilege + lifecycle](controls/bedrock/agent/) | 8 | 1 ([`bedrock_agent_overpermissioned`](chains/bedrock_agent_overpermissioned.yaml)) |
| [SageMaker execution-role overprivilege + lifecycle](controls/sagemaker/) | 8 | 1 ([`sagemaker_training_role_overprivileged`](chains/sagemaker_training_role_overprivileged.yaml)) |
| [AI data-boundary violations (RAG indexing PHI, cross-account training)](chains/bedrock_rag_phi_exposure.yaml) | 6 | 1 ([`bedrock_rag_phi_exposure`](chains/bedrock_rag_phi_exposure.yaml)) |
| [Cross-service AI compounds (agent → Lambda → S3, notebook → prod role)](chains/bedrock_agent_tool_phi_exposure.yaml) | 4 | 2 ([`bedrock_agent_tool_phi_exposure`](chains/bedrock_agent_tool_phi_exposure.yaml), [`sagemaker_notebook_production_escape`](chains/sagemaker_notebook_production_escape.yaml)) |
| [Shadow agent governance + ghost references](controls/bedrock/agent/) | 6 | 0 |
| **Total** | **32** | **5** ([taxonomy](docs/ai-agent-identity-taxonomy.md)) |

Every AI control maps to the OWASP Non-Human Identity (NHI) Top 10 — see [`docs/compliance/owasp-nhi-top10.md`](docs/compliance/owasp-nhi-top10.md) for the full 235-control mapping.

## Scanners vs Risk Reasoners

| | Checklist scanners | Stave |
|---|---|---|
| **Checks** | Individual settings on individual resources | Compositions across multiple resources |
| **Finds** | "Bucket not encrypted" (attribute) | "This bucket is reachable through an unauthenticated identity pool" (path) |
| **Knows your intent?** | No — universal baselines | Yes — reads your tags, trust policies, and declared purpose |
| **Output** | Hundreds of findings, most are known | A handful of compound chains, each naming root cause and fix |
| **Proof** | Scan result (point-in-time opinion) | Deterministic, traceable evidence chain |
| **Credentials** | Requires cloud API access | Runs on static snapshots — air-gapped, no credentials |

Stave doesn't replace your scanner. It finds what your scanner structurally cannot — the compound risks that exist in the relationships between individually-correct configurations.

## Operating model

Static configuration snapshots in, deterministic findings out. No cloud credentials, no API calls, no network access. Same inputs produce the same outputs; every conclusion carries the evidence chain that derived it.

## Catalog at a glance

- **2891 built-in controls across 85 domains** — S3, IAM, VPC, EC2, RDS, Lambda, ECS, EKS, CloudTrail, KMS, OpenSearch, SageMaker, Bedrock, Cognito, and [71 more](docs/controls/reference.md).
- **23 ghost-reference controls** — cross-inventory detection of pointers to deleted resources (IAM → role, agent → Lambda, CNAME → S3 bucket). Single-resource scanners can't see absence.
- **618 compound chain definitions** — multi-step attack paths across identity, data, audit, and recovery surfaces; 5 of those land on AI agent identity (Bedrock + Lambda + S3 PHI, RAG → PHI, notebook → prod role).
- **10 compliance profiles** — HIPAA, CIS AWS v3.0, SOC 2, PCI-DSS v4.0, NIST 800-53, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF 2.0.
- **Coverage benchmarks** — Full OWASP Top 10, 15/15 ATT&CK cloud techniques tested by Atomic Red Team, 20/21 Rhino Security Labs privilege-escalation techniques, 78/78 AWS CIRT Threat Technique Catalog configuration preconditions.

## Why these controls exist

Every control in the catalog traces to a documented security failure — HackerOne disclosures, public breach postmortems, AWS security advisories, and Mandiant/GTIG incident reports. The catalog wasn't designed from a compliance checklist. It was built backward from how infrastructure actually gets compromised.

See [docs/index.md](docs/index.md) for the full feature index: drift, watch, rank, bundle, graph export, custom controls, CI gating, SARIF, evidence bundles.

## Install

Three options, lowest-friction first. All three end at the same first command — `bash examples/demo-ai-security/run.sh` — and all three honor every flag/path in the [workflow guides](docs/workflows/).

### Option 1 — Coder workspace (recommended; zero setup)

A pre-configured workspace with `stave`, `stave-mcp`, Steampipe, the full catalog, and every example already in place:

```bash
# From a checkout of this repo:
coder templates push stave --directory stave-workspace
coder create my-stave --template stave
```

See [`stave-workspace/README.md`](stave-workspace/README.md) for import, customization (own fork, additional Steampipe plugins), and what the template does and doesn't include.

### Option 2 — Docker (no Coder required)

Same image, run directly:

```bash
# Build from this checkout (no daemon-side Coder needed):
cd stave && docker build -f stave-workspace/Dockerfile -t stave-workspace:edge .
docker run --rm -it stave-workspace:edge bash -lc 'bash ~/examples/demo-ai-security/run.sh'
```

### Option 3 — Local install (contributors and power users)

```bash
go install github.com/sufield/stave/cmd/stave@latest
go install github.com/sufield/stave/cmd/mcp@latest
# Or build from a clone:
git clone https://github.com/sufield/stave.git && cd stave && make build
```

For formal verification, blast-radius enumeration, or compound-attack proofs, install the optional [reasoning engines](docs/index.md) (Z3, cvc5, Soufflé, Clingo, Prolog, PySAT) — or click **Open in Codespaces** above, which pre-installs all of them.

## Quick start

### New here? The 5-minute workflow

You know your AWS services; Stave tells you what to collect, then evaluates it.

```bash
stave discover --services iam,s3,ec2,lambda,cloudtrail   # what to collect (read-only API calls)
stave plan     --services iam,s3,ec2,lambda,cloudtrail   # what will be checked, by severity
# collect raw snapshots with your tool (AWS CLI/Steampipe/Pulumi), then convert:
stave transform -i ./raw -o ./observations               # built-in jq conversion to obs.v0.1
stave apply --services iam -o ./observations             # findings, per service group
stave check --before ./observations --after ./observations-fixed   # resolved / remaining / new
```

Or run `scripts/quickstart.sh`. Full walkthrough: [`docs/WORKFLOW.md`](docs/WORKFLOW.md).
Stave never has AWS credentials — it reads the `obs.v0.1` observations you convert.

### Try a demo against a bundled snapshot (30 seconds, zero AWS access)

```bash
bash examples/demo-s3-public-read/run.sh        # Public S3 bucket
bash examples/demo-ai-security/run.sh           # Bedrock + Lambda + S3 PHI
```

### Run against your own AWS account (5 minutes)

```bash
bash scripts/aws-snapshot.sh ./my-snapshot      # collect (read-only AWS CLI) + stave transform
stave apply --observations ./my-snapshot/observations
```

See [`docs/quickstart-own-data.md`](docs/quickstart-own-data.md) for prerequisites, the property mapping, and the time-budget breakdown.

**Bring your own data:** the built-in `stave transform -i raw/ -o observations/` (jq filters) converts raw AWS CLI snapshots to `obs.v0.1` by default. For breadth beyond the built-in filters, see [`examples/agents/`](examples/agents/) for templates that transform Steampipe output into Stave observations.

### Long form — workflow for a real project

```bash
# Place observation snapshots in observations/
# (at least two snapshots for duration-based controls)

# Validate inputs
stave validate

# Evaluate and produce findings
stave apply

# Investigate unexpected results
stave diagnose
```

## How it works

The pipeline is **Discover → Collect → Transform → Apply → Act**. Three of the five steps are built-in commands.

1. **Discover.** `stave discover --services iam,s3,ec2` resolves your services to a collection manifest — the exact read-only API calls, observation signals, and minimum IAM permissions you need. Nothing runs against AWS; it just tells you what to collect.
2. **Collect.** Run the AWS CLI calls from the manifest. The bundled `scripts/aws-snapshot.sh` does this for you, or use Steampipe, Terraform state, or any tool that produces raw JSON. This is the only step that touches your cloud.
3. **Transform.** `stave transform -i raw/ -o observations/` converts raw AWS CLI JSON into `obs.v0.1` observations using embedded jq filters — in-process, no external `jq` needed. Sensitive values (UserData, env vars, secret-keyed tags) are hashed; policy documents, ARNs, and actions are left intact.
4. **Apply.** `stave apply` evaluates each control's predicate against each asset, then composes the resulting findings into compound chains (multiple co-failing controls on related assets = one chain finding).
5. **Act.** Findings ship with explicit remediation, severity, and the evidence chain that justified them. Optionally pipe to nine external reasoning engines (Z3, Soufflé, Clingo, Prolog, …) for formal proofs, blast-radius enumeration, or attacker-cost ROI.

Full architecture in [docs/architecture/overview.md](docs/architecture/overview.md). The reasoning-engine catalog and what each one answers: [docs/engines.md (in docs/index.md)](docs/index.md).

## Compliance profiles

```bash
stave apply --profile hipaa --input observations.json --include-all
# Also: cis-aws-v3.0, soc2, pci-dss-v4.0, nist-800-53, fedramp,
#       gdpr, ffiec, iso-27001, nist-csf-2.0
```

## CI/CD

```bash
stave ci baseline save
stave apply --format sarif > results.sarif          # for GitHub Security
stave apply --format json | stave ci gate --fail-on new
```

## Custom controls

New controls are YAML — no Go changes required. The `forge` toolchain handles the full lifecycle:

```bash
stave forge paths --snapshot obs.json --asset-type aws_s3_bucket    # 1. discover fields
stave forge preview --snapshot obs.json --field ... --op eq --value true  # 2. test predicate
stave forge new --id CTL.S3.TAGS.001 --name "..." --field ... --severity high  # 3. generate control + fixtures
stave forge test --control controls/s3/... --pass fix-pass.json --fail fix-fail.json  # 4. TDD
stave forge lint --control controls/s3/ --semantic --strict         # 5. static analysis
stave validate --controls controls/ --observations obs/             # 6. structural check
stave apply --controls ./my-controls --observations obs/            # 7. end-to-end proof
```

Controls are `unsafe_predicate:` match rules (`all:`/`any:` groups of `field`/`op`/`value`). Point `stave apply --controls ./my-controls` at any directory and the engine evaluates them alongside the built-in catalog. See [authoring controls](docs/controls/authoring.md).

## Built-in controls

2891 controls across 85 domains. Largest surfaces today: AWS S3 (131), AWS IAM (219), AWS OpenSearch (132), GCP Cloud Storage (7), DNS (3, vendor-agnostic dangling-reference detection).

Full reference and per-domain breakdowns: [`docs/controls/reference.md`](docs/controls/reference.md).

## Documentation

| | |
|---|---|
| [Quickstart](docs/time-to-first-finding.md) | Get your first finding in 5 minutes |
| [Building an extractor](docs/extractor-prompt.md) | Steampipe, CloudQuery, AWS Config, or custom |
| [Authoring controls](docs/controls/authoring.md) | Write custom YAML controls with the forge toolchain |
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
| [Community](https://www.reddit.com/r/systeminvariant/) | Join the discussion on Reddit |
| [Full docs index](docs/index.md) | Everything else |

## Community

Join our community on Reddit to discuss system invariants, cloud safety, and the development of Stave:

- **Reddit:** [/r/systeminvariant](https://www.reddit.com/r/systeminvariant/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, development workflow, and PR guidelines.

## License

[Apache License 2.0](LICENSE)

# DigitalOcean Marketplace listing — Stave

Copy for the DO Vendor Portal submission. Each section maps to a
field in the submission form.

---

## Name

Stave — Cloud Security Evaluation

## One-line summary

Deterministic cloud security evaluation — 2,650+ controls against
configuration snapshots. Air-gapped, no credentials, reproducible
verdicts.

## Description

Stave evaluates cloud configuration snapshots against a catalog of
2,650+ controls and 585+ compound-risk chains. It produces
deterministic verdicts (same inputs → same output, every time) and
finds the *combinations* of conditions that single-resource scanners
structurally miss — the IAM role plus the security group plus the S3
bucket that, together, compose into an exploitable path.

This droplet is pre-configured for the full evaluation loop:

- **`stave`** — the CLI, evaluates a snapshot directory and prints
  findings in text, JSON, or SARIF.
- **`stave-mcp`** — the MCP server, exposes 14 tools so an AI
  assistant (Claude Desktop, VS Code MCP, anything stdio-MCP) can
  call Stave in conversation. Renders interactive HTML
  visualizers: posture dashboard, compliance scorecard, risk chain
  graph.
- **Steampipe** + AWS plugin — collect AWS state and transform it
  into Stave's `obs.v0.1` snapshot format. The mapping query is in
  the bundled guides.
- **Workflow guides** — six numbered walkthroughs covering the full
  loop: Steampipe → evaluation → chain triage → fix → compliance
  evidence → CI gate.

All evaluation is **offline**: no network calls, no cloud credentials
required during the evaluation itself. AWS credentials are only
needed to *collect* snapshots; they're never sent to Stave.

## Quick start (what the MOTD prints on SSH)

```
ssh root@<droplet-ip>

# Demo: evaluate a bundled fixture (60 seconds, no AWS access)
bash ~/examples/demo-ai-security/run.sh

# Visualize: posture dashboard
stave-mcp --demo-dashboard --observations ~/examples/demo-ai-security/obs

# Your own AWS account (after `aws configure`):
mkdir -p ~/obs
steampipe query "select * from aws_s3_bucket" --output json > ~/obs/s3.json
stave apply --observations ~/obs/

# Six numbered guides cover the full workflow
ls ~/guides/
```

## Included software (pinned)

| | Version |
|---|---|
| Ubuntu | 24.04 LTS (DO base image) |
| Go | 1.27.0 |
| Steampipe | 1.0.0 |
| AWS plugin | latest at build time |
| Stave | tagged release (see image notes) |
| Stave MCP server | same release |

No agents. No daemons. No background phone-home.

## Recommended droplet size

| Workload | Size | Cost |
|---|---|---|
| Demo + small-account evaluation | `s-1vcpu-1gb` | ~$6/mo |
| Realistic SOC 2 / HIPAA workload | `s-2vcpu-2gb` | ~$12/mo |
| Large-account / multi-region | `s-4vcpu-8gb` or above | ~$48/mo+ |

`stave apply` is single-pass over snapshots; CPU and memory scale
with snapshot size, not with the catalog. The $6 droplet runs the
bundled demo comfortably and handles a typical small-to-mid
AWS-account snapshot.

## Use cases

- **SOC 2 / HIPAA / PCI-DSS evidence** — render a deterministic
  compliance scorecard against the embedded framework profiles
  (CIS AWS v3.0, HIPAA, PCI-DSS v4.0, FedRAMP Moderate, SOC 2,
  and more).
- **Pre-audit posture review** — find the compound-risk paths an
  auditor will ask about before the auditor does.
- **CI pipeline gate** — `stave apply --format json | stave ci gate
  --policy fail_on_any_violation --in -` returns exit 3 on
  violation, blocking the merge.
- **AI-assisted security** — point Claude Desktop / VS Code MCP
  at the running `stave-mcp` and ask in plain English ("explain
  CTL.S3.PUBLIC.001", "evaluate the snapshot at ~/obs").

## What this image does NOT do

- Does not include or require AWS credentials. You configure
  `aws configure` (or IAM roles for instance metadata) yourself.
- Does not call home. All evaluation is local; the only network
  needed is Steampipe → AWS (which runs against AWS endpoints
  directly, not via DigitalOcean or Stave).
- Does not include code-server or any browser-based IDE. The
  droplet is SSH-first; install your editor of choice or use the
  separate Coder workspace template if you want an in-browser IDE.

## Support

- Documentation: <https://github.com/sufield/stave/tree/main/docs/workflows>
- Issues: <https://github.com/sufield/stave/issues>
- License: Apache-2.0

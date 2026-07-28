# Integrations

Demos showing how stave works with other tools. Each integration
follows the same structure: prerequisites, install, run.

### Input — tools that feed data into stave

| Integration | Demo |
|---|---|
| [Terraform State](terraform-state/) | Evaluate S3 resources from tfstate |
| [AWS Config](aws-config/) | Evaluate from AWS Config snapshots |
| [Steampipe](steampipe/) | SQL query to observation snapshot |

#### Choosing between input integrations

| Source | Best when | Trade-off |
|---|---|---|
| Terraform State | The tfstate is the source of truth and drift is rare | Misses anything created outside Terraform |
| AWS Config | The account already runs AWS Config and you want point-in-time history | Config record shape lags real attributes; per-account setup |
| Steampipe | You need live cloud state across many services without Config enrolment | Requires Steampipe credentials + a small SQL/jq pipeline |

Use the source that matches your evidence boundary. Mix them when one
source can't see everything you need (see below).

#### Multi-source aggregation

`stave apply` reads every `obs.v0.1` file in the `--observations`
directory regardless of which extractor produced it. To aggregate
sources, drop their outputs into the same directory:

```
observations/
  steampipe-s3-2026-04-30T12-00-00Z.json     # Steampipe → S3 buckets
  steampipe-iam-2026-04-30T12-00-00Z.json    # Steampipe → IAM roles
  tfstate-network-2026-04-30T12-00-00Z.json  # Terraform → VPC + SGs
  awsconfig-2026-04-30T12-00-00Z.json        # AWS Config → everything else
```

Stave merges them into a single evaluation pass. There is no manifest
to maintain — file presence is the contract.

##### When to mix sources

- **Coverage gaps.** Terraform owns the network, click-ops created the
  S3 buckets — pull buckets from Steampipe, networking from tfstate.
- **Drift verification.** Compare tfstate against live state by
  emitting both and watching for control disagreement on the same
  asset ID.
- **Cross-account / cross-cloud.** One Steampipe extractor per account,
  same `observations/` directory.

##### Provenance and the unknown-source flag

Each observation carries `generated_by.source_type` so findings can be
traced back to the producing extractor. Steampipe and other custom
producers use source types stave does not ship a schema for; the
loader accepts them by default. Built-in sources (Terraform State,
AWS Config) carry recognized source types.

### Output — tools that consume stave findings

| Integration | Demo |
|---|---|
| [GitHub Actions + SARIF](github-actions-sarif/) | Violations in PR diffs |
| [Cloud Custodian](cloud-custodian/) | Detect with stave, remediate with Custodian |
| [Slack Webhook](slack-webhook/) | Alert on violations in CI |

### Workflow — stave as part of a development process

| Integration | Demo |
|---|---|
| [pre-commit](pre-commit/) | Validate before every commit |
| [Atlantis](atlantis/) | Post-plan safety check on PRs |

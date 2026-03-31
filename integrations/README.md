# Integrations

Demos showing how stave works with other tools. Each integration
follows the same structure: prerequisites, install, run.

### Input — tools that feed data into stave

| Integration | Demo |
|---|---|
| [Terraform State](terraform-state/) | Scan S3 resources from tfstate |
| [AWS Config](aws-config/) | Scan from AWS Config snapshots |
| [Steampipe](steampipe/) | SQL query to observation snapshot |

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

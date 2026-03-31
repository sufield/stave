# Integrations

Demos showing how stave works with other tools. Each integration
follows the same structure: prerequisites, install, run.

Stave integrates through two surfaces:

- **Input**: any tool that produces JSON can feed stave via `obs.v0.1`
- **Output**: stave produces JSON, SARIF, or text that other tools consume

| Integration | Direction | Demo |
|---|---|---|
| [GitHub Actions + SARIF](github-actions-sarif/) | Output | Violations in PR diffs |
| [Terraform State](terraform-state/) | Input | Scan S3 resources from tfstate |
| [pre-commit](pre-commit/) | Workflow | Validate before every commit |
| [AWS Config](aws-config/) | Input | Scan from AWS Config snapshots |
| [Cloud Custodian](cloud-custodian/) | Output | Detect with stave, remediate with Custodian |
| [Steampipe](steampipe/) | Input | SQL query to observation snapshot |
| [Slack Webhook](slack-webhook/) | Output | Alert on violations in CI |
| [Atlantis](atlantis/) | Workflow | Post-plan safety check on PRs |

# Import Your Snapshots

Stave evaluates `obs.v0.1` JSON snapshots. Three ways to produce them.

## Option 1: aws CLI + jq

Capture directly from the AWS APIs using the included collector script.
See the [snapshot-your-account skill](../../internal/_skills/snapshot-your-account/SKILL.md)
for a guided walkthrough.

```bash
# Requires: AWS credentials with read-only access
# See docs/trust/collector-policy.md for the minimum IAM policy
```

## Option 2: Steampipe

Query cloud state via SQL and convert to `obs.v0.1`.
See [integrations/steampipe/](../../internal/integrations/steampipe/) for setup.

## Option 3: AWS Config

Convert AWS Config snapshots to `obs.v0.1`.
See [integrations/aws-config/](../../internal/integrations/aws-config/) for setup.

## Multi-source aggregation

`stave apply` reads every `obs.v0.1` file in `--observations` regardless
of which extractor produced it. Drop outputs from multiple sources into
the same directory to combine coverage.

## What's next

- [CI integration](ci-integration.md) — automate evaluation
- [Collector IAM policy](../trust/collector-policy.md) — audit the required permissions

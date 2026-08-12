# Steampipe

Query S3 bucket configurations with SQL and feed the results to stave.

## Prerequisites

- Ubuntu 24
- AWS CLI configured with credentials
- jq
- stave binary installed

## Install

```bash
# Install Steampipe
sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
steampipe plugin install aws

# Install stave
git clone https://github.com/sufield/stave.git /tmp/stave
cd /tmp/stave && make build
sudo cp /tmp/stave/stave /usr/local/bin/
```

Save the extractor script:

```bash
cat > extract-steampipe-s3.sh << 'SCRIPT'
#!/bin/bash
# Queries S3 configs via Steampipe and outputs obs.v0.1 JSON
set -euo pipefail
steampipe query --output json "
  select
    name,
    region,
    versioning_enabled,
    logging,
    server_side_encryption_configuration,
    block_public_acls,
    ignore_public_acls,
    block_public_policy,
    restrict_public_buckets,
    tags_src
  from aws_s3_bucket
" | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "steampipe", tool: "steampipe"},
  captured_at: (now | todate),
  assets: [.[] | {
    id: .name,
    type: "aws_s3_bucket",
    vendor: "aws",
    properties: {
      storage: {
        kind: "bucket",
        name: .name,
        region: .region,
        versioning: {
          enabled: (.versioning_enabled // false)
        },
        logging: {
          enabled: (.logging != null),
          target_bucket: (.logging.TargetBucket // "")
        },
        encryption: {
          algorithm: (.server_side_encryption_configuration.SSEAlgorithm // "none"),
          kms_key_id: (.server_side_encryption_configuration.KMSMasterKeyID // "")
        },
        controls: {
          public_access_block: {
            block_public_acls: (.block_public_acls // false),
            ignore_public_acls: (.ignore_public_acls // false),
            block_public_policy: (.block_public_policy // false),
            restrict_public_buckets: (.restrict_public_buckets // false)
          },
          public_access_fully_blocked:
            ((.block_public_acls // false)
              and (.ignore_public_acls // false)
              and (.block_public_policy // false)
              and (.restrict_public_buckets // false))
        },
        tags: ((.tags_src // []) | map({(.Key): .Value}) | add // {})
      }
    }
  }]
}'
SCRIPT
chmod +x extract-steampipe-s3.sh
```

## Field Mapping: S3

| Steampipe Column                          | Stave Property Path                                                       |
|-------------------------------------------|---------------------------------------------------------------------------|
| `name`                                    | `properties.storage.name` and `id`                                        |
| `region`                                  | `properties.storage.region`                                               |
| `versioning_enabled`                      | `properties.storage.versioning.enabled`                                   |
| `logging`                                 | `properties.storage.logging.enabled` / `target_bucket`                    |
| `server_side_encryption_configuration`    | `properties.storage.encryption.algorithm` and `kms_key_id`                |
| `block_public_acls`                       | `properties.storage.controls.public_access_block.block_public_acls`       |
| `ignore_public_acls`                      | `properties.storage.controls.public_access_block.ignore_public_acls`      |
| `block_public_policy`                     | `properties.storage.controls.public_access_block.block_public_policy`     |
| `restrict_public_buckets`                 | `properties.storage.controls.public_access_block.restrict_public_buckets` |
| (computed AND of the four above)          | `properties.storage.controls.public_access_fully_blocked`                 |
| `tags_src`                                | `properties.storage.tags`                                                 |

For the canonical query that uses Postgres `json_build_object`
directly (no jq required), see the Steampipe mapping contract.
The shell-script form above is the lowest-friction starter; the
contract form is the production reference.

## Run

```bash
# Extract all S3 buckets via Steampipe
mkdir -p observations
./extract-steampipe-s3.sh > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json

# Evaluate
stave apply \
  --observations observations \
  --max-unsafe 0s \
  --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --format text
```

Steampipe's `source_type` ("steampipe") isn't in stave's built-in
connector registry, but stave accepts unknown or custom source types
by default, so no extra flag is needed.

## Sample observation

[`template-observation.json`](template-observation.json) shows the
expected output shape any extraction pipeline (Steampipe, CloudQuery,
custom scripts) should produce. Use it as the reference target when
authoring a new extractor.

## What you see

Steampipe queries all S3 buckets in your AWS account using SQL. The
extractor maps the results to `obs.v0.1` format. Stave evaluates
each bucket against the built-in controls and reports violations.

## CI/CD examples

### GitHub Actions

```yaml
# .github/workflows/stave-steampipe.yml
name: Stave / Steampipe

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # daily

permissions:
  contents: read
  security-events: write  # required for SARIF upload

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_READ_ROLE }}
          aws-region: us-east-1

      - name: Install Steampipe
        run: |
          sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
          steampipe plugin install aws

      - name: Install stave
        run: |
          curl -fsSL https://github.com/sufield/stave/releases/latest/download/stave-linux-amd64 \
            -o /usr/local/bin/stave
          chmod +x /usr/local/bin/stave

      - name: Extract observations
        run: |
          mkdir -p observations
          ./extract-steampipe-s3.sh \
            > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json

      - name: Evaluate
        run: |
          stave apply \
            --observations observations \
            --max-unsafe 0s \
            --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
            --format sarif > stave.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: stave.sarif
```

The job exits non-zero (exit code 3) when stave reports findings, so
the workflow fails on non-compliant configurations. The SARIF upload
populates the GitHub **Security** tab with one entry per finding.

### GitLab CI

```yaml
# .gitlab-ci.yml
stages: [evaluate]

stave:
  stage: evaluate
  image: ubuntu:24.04
  before_script:
    - apt-get update && apt-get install -y curl jq awscli
    - sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
    - steampipe plugin install aws
    - curl -fsSL https://github.com/sufield/stave/releases/latest/download/stave-linux-amd64 \
        -o /usr/local/bin/stave
    - chmod +x /usr/local/bin/stave
  script:
    - mkdir -p observations
    - ./extract-steampipe-s3.sh > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json
    - stave apply
        --observations observations
        --max-unsafe 0s
        --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ)
       
        --format sarif > stave.sarif
  artifacts:
    when: always
    reports:
      sast: stave.sarif
    paths:
      - stave.sarif
  allow_failure: false
```

GitLab consumes the SARIF artifact through its `sast` report type;
the job fails (non-zero exit) on findings exactly like the GitHub
workflow.

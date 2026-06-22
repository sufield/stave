# AWS Config

Extract S3 bucket configurations from AWS Config and evaluate them
with stave.

## Prerequisites

- Ubuntu 24
- AWS CLI configured with credentials
- AWS Config enabled and recording S3 resources
- jq
- stave binary installed

## Install

```bash
# Install AWS CLI and jq
sudo apt-get update && sudo apt-get install -y awscli jq

# Install stave
git clone https://github.com/sufield/stave.git /tmp/stave
cd /tmp/stave && make build
sudo cp /tmp/stave/stave /usr/local/bin/
```

Save the extractor script:

```bash
cat > extract-aws-config-s3.sh << 'SCRIPT'
#!/bin/bash
# Extracts S3 configs from AWS Config as obs.v0.1 JSON
set -euo pipefail
BUCKET="${1:?Usage: $0 <bucket-name>}"

aws configservice get-resource-config-history \
  --resource-type AWS::S3::Bucket \
  --resource-id "$BUCKET" \
  --limit 1 \
  --output json | jq --arg bucket "$BUCKET" '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "aws-config", tool: "aws-cli"},
  captured_at: .configurationItems[0].configurationItemCaptureTime,
  assets: [.configurationItems[] | {
    id: $bucket,
    type: "aws_s3_bucket",
    vendor: "aws",
    properties: {
      storage: {
        kind: "bucket",
        name: $bucket,
        tags: ((.supplementaryConfiguration.TagSet // [])
          | map({(.key): .value}) | add // {})
      }
    }
  }]
}'
SCRIPT
chmod +x extract-aws-config-s3.sh
```

## Run

```bash
# Extract a bucket's config from AWS Config
mkdir -p observations
./extract-aws-config-s3.sh my-bucket > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json

# Evaluate
stave apply \
  --observations observations \
  --max-unsafe 0s \
  --now $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --format text
```

## What you see

Stave evaluates the S3 bucket configuration captured by AWS Config.
AWS Config provides the historical state — stave evaluates the safety
of that state against the built-in control pack.

## Field Mapping: S3

| AWS Config field | obs.v0.1 path |
|---|---|
| Resource ID (`$bucket`) | `id`, `properties.storage.name` |
| `supplementaryConfiguration.TagSet` | `properties.storage.tags` |
| `supplementaryConfiguration.BucketVersioningConfiguration.status` | `properties.storage.versioning.enabled` (map `Enabled` → `true`) |
| `supplementaryConfiguration.ServerSideEncryptionConfiguration` | `properties.storage.encryption.algorithm` / `kms_key_id` |
| `supplementaryConfiguration.PublicAccessBlockConfiguration` | `properties.storage.public_access_block.*` |

The starter script above only maps the tag set; extend the jq pipeline
with the rows above to evaluate encryption and public-access-block
controls.

## Other resource types

`aws configservice get-resource-config-history` works for every
`AWS::*::*` type AWS Config records — IAM roles, EC2 instances,
security groups, RDS clusters. The shape of
`supplementaryConfiguration` differs per type; use
`stave forge paths --in observation.json` to discover the paths the
built-in controls expect for a given asset.

## CI/CD

The Steampipe integration ships full GitHub Actions and GitLab CI
examples that work the same way for the AWS Config extractor — only
the extract step differs. See
[`integrations/steampipe/README.md`](../steampipe/README.md#cicd-examples).

## Mixing with other sources

Drop AWS Config observations and Steampipe / Terraform observations
into the same `observations/` directory; stave merges them in one
pass. See
[`integrations/README.md`](../README.md#multi-source-aggregation).

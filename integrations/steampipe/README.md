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
        versioning: {
          enabled: (.versioning_enabled // false)
        },
        logging: {
          enabled: (.logging != null),
          target_bucket: (.logging.TargetBucket // "")
        },
        tags: ((.tags_src // []) | map({(.Key): .Value}) | add // {})
      }
    }
  }]
}'
SCRIPT
chmod +x extract-steampipe-s3.sh
```

## Run

```bash
# Extract all S3 buckets via Steampipe
mkdir -p observations
./extract-steampipe-s3.sh > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json

# Evaluate
stave apply \
  --observations observations \
  --max-unsafe 0s \
  --now $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --allow-unknown-input \
  --format text
```

## What you see

Steampipe queries all S3 buckets in your AWS account using SQL. The
extractor maps the results to `obs.v0.1` format. Stave evaluates
each bucket against the built-in controls and reports violations.

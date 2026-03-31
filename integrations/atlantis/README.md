# Atlantis

Run stave as a post-plan safety check in Atlantis PR workflows.

## Prerequisites

- Ubuntu 24
- Atlantis server running (https://www.runatlantis.io/)
- Terraform project with S3 resources
- stave binary available on the Atlantis server

## Install

Install stave on the Atlantis server:

```bash
git clone https://github.com/sufield/stave.git /tmp/stave
cd /tmp/stave && make build
sudo cp /tmp/stave/stave /usr/local/bin/
```

Save the Terraform extractor on the Atlantis server:

```bash
cat > /usr/local/bin/extract-tf-s3.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
terraform show -json "$1" | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "terraform-plan", tool: "terraform"},
  captured_at: (now | todate),
  assets: [
    .values.root_module.resources[]
    | select(.type == "aws_s3_bucket")
    | {
        id: .values.bucket,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: {
          storage: {
            kind: "bucket",
            name: .values.bucket,
            tags: (.values.tags // {})
          }
        }
      }
  ]
}'
SCRIPT
chmod +x /usr/local/bin/extract-tf-s3.sh
```

Add the stave check to your `atlantis.yaml`:

```bash
cat > atlantis.yaml << 'EOF'
version: 3
projects:
  - dir: .
    workflow: stave-check
workflows:
  stave-check:
    plan:
      steps:
        - init
        - plan
    policy_check:
      steps:
        - run: |
            mkdir -p /tmp/stave-obs
            extract-tf-s3.sh $PLANFILE > /tmp/stave-obs/snap.json
            stave apply \
              --observations /tmp/stave-obs \
              --max-unsafe 0s \
              --allow-unknown-input \
              --format text
EOF
```

## Run

1. Open a pull request that modifies Terraform S3 resources
2. Atlantis runs `terraform plan` then the stave policy check
3. If stave finds violations, Atlantis comments on the PR with the
   findings and blocks the apply

## What you see

Atlantis posts a comment on the PR:

```
Policy Check — stave-check

Violations
----------
1. CTL.S3.PUBLIC.001
   No Public S3 Buckets
   Asset: my-public-bucket
   ...

Exit code 3 — violations found. Apply blocked.
```

Fix the Terraform config, push, and Atlantis re-runs the check.

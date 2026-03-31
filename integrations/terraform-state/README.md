# Terraform State

Extract S3 bucket configurations from Terraform state and evaluate
them with stave.

## Prerequisites

- Ubuntu 24
- Docker (for stave) or stave binary installed
- Terraform 1.x with an existing S3 state

## Install

```bash
# Install Terraform
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y terraform jq

# Install stave
git clone https://github.com/sufield/stave.git
cd stave && make build
export PATH=$PWD:$PATH
```

Save the extractor script:

```bash
cat > extract-tf-s3.sh << 'SCRIPT'
#!/bin/bash
# Extracts S3 bucket configs from Terraform state as obs.v0.1 JSON
set -euo pipefail
terraform show -json | jq '{
  schema_version: "obs.v0.1",
  generated_by: {source_type: "terraform-state", tool: "terraform"},
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
            tags: (.values.tags // {}),
            versioning: {
              enabled: ((.values.versioning[0].enabled // false) == true)
            }
          }
        }
      }
  ]
}'
SCRIPT
chmod +x extract-tf-s3.sh
```

## Run

```bash
# In your Terraform project directory
cd my-terraform-project

# Extract S3 state as a stave observation
mkdir -p observations
./extract-tf-s3.sh > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json

# Evaluate with stave built-in controls
stave apply \
  --observations observations \
  --max-unsafe 0s \
  --now $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --allow-unknown-input \
  --format text
```

## What you see

Stave evaluates the S3 buckets from your Terraform state against the
built-in control pack. Any bucket missing versioning, encryption, or
public access block is flagged with remediation guidance.

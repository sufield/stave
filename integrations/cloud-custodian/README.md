# Cloud Custodian

Stave detects misconfigurations. Cloud Custodian remediates them.

## Prerequisites

- Ubuntu 24
- Python 3
- AWS CLI configured with credentials
- stave binary installed

## Install

```bash
# Install Cloud Custodian
pip install c7n

# Install stave
git clone https://github.com/sufield/stave.git /tmp/stave
cd /tmp/stave && make build
sudo cp /tmp/stave/stave /usr/local/bin/
```

## Run

Step 1 — Stave detects which buckets are violating:

```bash
stave apply \
  --controls controls/s3 \
  --observations observations \
  --max-unsafe 0s \
  --format json \
  | jq -r '.findings[].resource_id' > violating-buckets.txt
```

Step 2 — Create a Cloud Custodian policy that acts on those buckets:

```bash
cat > remediate-public-buckets.yml << 'EOF'
policies:
  - name: block-public-s3
    resource: s3
    filters:
      - type: value
        key: Name
        op: in
        value_from:
          url: file://violating-buckets.txt
          format: txt
    actions:
      - type: set-public-block
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
EOF
```

Step 3 — Custodian remediates:

```bash
custodian run -s output remediate-public-buckets.yml
```

## What you see

Stave identifies the unsafe buckets. Cloud Custodian enables Public
Access Block on each one. Run stave again to confirm the fix:

```bash
# Re-extract observations after remediation
# ... (run your extractor)

stave apply --observations observations --max-unsafe 0s --format text
# Exit code 0 — no violations
```

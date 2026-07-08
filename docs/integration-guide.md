# Integration Guide: Stave with Companion Tools

Stave evaluates offline JSON snapshots — it never holds cloud
credentials. This means any tool that can produce JSON from cloud
APIs can feed Stave's evaluation engine. This guide shows how.

## Quick Reference

| Combination | Use Case |
|-------------|----------|
| Stave + CloudQuery | Scheduled CI/CD snapshot collection for 300+ AWS resource types |
| Stave + Steampipe | Ad-hoc queries, interactive exploration, coverage validation |
| Stave + AWS Config | Zero new tooling for teams already running Config |
| Stave standalone | Built-in jq transform from raw AWS CLI output |

All paths produce the same `obs.v0.1` JSON. Stave's controls and
compound chains evaluate identically regardless of how observations
were created.

## Stave + CloudQuery

**Problem:** Stave has controls for SageMaker, Bedrock, EKS, and 60+
other services but doesn't natively collect their API responses.

**Solution:** CloudQuery syncs AWS resources to a local database.
Query the synced data, transform to obs.v0.1, evaluate with Stave.

### Setup

```bash
# Install CloudQuery
brew install cloudquery/tap/cloudquery

# Create sync config (aws.yml)
cat > aws.yml <<'YAML'
kind: source
spec:
  name: aws
  path: cloudquery/aws
  registry: cloudquery
  tables: ["aws_s3_buckets", "aws_iam_roles", "aws_iam_policies",
           "aws_ec2_instances", "aws_lambda_functions",
           "aws_sagemaker_notebook_instances"]
  destinations: ["sqlite"]
---
kind: destination
spec:
  name: sqlite
  path: cloudquery/sqlite
  registry: cloudquery
  spec:
    connection_string: ./cloudquery.db
YAML

# Sync
cloudquery sync aws.yml
```

### Transform and Evaluate

```bash
# Extract S3 observations
sqlite3 -json cloudquery.db \
  "SELECT name, versioning_status, server_side_encryption_configuration,
          logging_target_bucket, block_public_acls, block_public_policy,
          ignore_public_acls, restrict_public_buckets
   FROM aws_s3_buckets" \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
      source: "deployed",
      assets: [.[] | {
        id: .name,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: {
          storage: {
            kind: "bucket",
            name: .name,
            versioning: { enabled: (.versioning_status == "Enabled") },
            encryption: { at_rest_enabled: (.server_side_encryption_configuration != null) },
            logging: { enabled: (.logging_target_bucket != null) },
            controls: { public_access_fully_blocked: (
              .block_public_acls and .block_public_policy and
              .ignore_public_acls and .restrict_public_buckets
            )}
          }
        }
      }]
    }' > observations/s3-snap.json

# Evaluate
stave apply -o observations/
```

### Service Coverage

Run `stave services inspect <service>` to see which CloudQuery tables
map to each service:

```bash
stave services inspect sagemaker
# Shows EXTERNAL COLLECTION SOURCES section with CloudQuery tables
```

12 services have CloudQuery table mappings in the registry: IAM, S3,
EC2, Lambda, ECS, EKS, RDS, VPC, CloudTrail, KMS, SageMaker, Bedrock.

### CI/CD Pipeline

```bash
# Nightly: sync → extract → evaluate → alert
cloudquery sync aws.yml
for svc in s3 iam ec2 lambda; do
  ./extractors/${svc}.sh > observations/${svc}-$(date -u +%Y-%m-%dT%H%M%SZ).json
done
stave apply -o observations/ --format json > findings.json
```

## Stave + Steampipe

**Problem:** You want to validate Stave's coverage against CIS
benchmarks, or use Steampipe's 150+ plugins for ad-hoc extraction.

**Solution:** Steampipe exposes cloud APIs as SQL tables. Query
directly, transform to obs.v0.1, evaluate with Stave.

### Setup

```bash
steampipe plugin install aws
```

### Extract and Evaluate

```bash
# Extract S3 observations via Steampipe
steampipe query --output json \
  "SELECT name, region, versioning_enabled,
          server_side_encryption_configuration,
          logging, acl, policy,
          public_access_block_configuration
   FROM aws_s3_bucket" \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
      source: "deployed",
      assets: [.[] | {
        id: .name,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: {
          storage: {
            kind: "bucket",
            name: .name,
            versioning: { enabled: (.versioning_enabled // false) },
            encryption: { at_rest_enabled: (.server_side_encryption_configuration != null) },
            logging: { enabled: (.logging != null) },
            controls: { public_access_fully_blocked: (
              .public_access_block_configuration.BlockPublicAcls and
              .public_access_block_configuration.BlockPublicPolicy and
              .public_access_block_configuration.IgnorePublicAcls and
              .public_access_block_configuration.RestrictPublicBuckets
            )}
          }
        }
      }]
    }' > observations/s3-snap.json

stave apply -o observations/
```

### Coverage Validation

Run Steampipe CIS alongside Stave on the same account to compare:

```bash
# Steampipe findings
steampipe check benchmark.cis_v300 --output json > steampipe-cis.json

# Stave findings (same account snapshot)
stave apply -o observations/ --format json > stave-findings.json
```

**Expected differences:**

- Steampipe finds per-resource CIS checks (password policy, MFA,
  encryption settings). Stave covers most of these — run
  `stave catalog gaps .stave-backlog/checklists/cis-aws-v3.yaml`
  to see the mapping.
- Stave finds compound risks Steampipe cannot: privilege escalation
  chains, cross-service blast radius, data perimeter completeness,
  temporal configuration drift. These come from 622 compound chains
  that reason across resource relationships.

## Stave + AWS Config

**Problem:** Your team already runs AWS Config and doesn't want
additional tooling.

**Solution:** Export Config snapshots, transform to obs.v0.1.

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceType, configuration
                WHERE resourceType = 'AWS::S3::Bucket'" \
  --output json \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
      source: "deployed",
      assets: [.Results[] | fromjson | {
        id: .resourceId,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: { storage: { kind: "bucket", name: .resourceId } }
      }]
    }' > observations/s3-snap.json

stave apply -o observations/
```

AWS Config covers 380+ resource types. Zero additional cost if
Config is already deployed.

## Standalone Stave

No companion tools needed. Use the AWS CLI + jq:

```bash
# Capture raw API responses
aws s3api list-buckets > raw/s3-buckets.json
aws s3api get-bucket-versioning --bucket my-bucket >> raw/s3-versioning.json

# Transform to obs.v0.1
stave transform -i raw/ -o observations/

# Evaluate
stave apply -o observations/
```

The built-in `stave transform` handles common AWS services. For
services without built-in transform support, use the extractor
pattern documented in `docs/extractor-prompt.md`.

## Choosing a Companion Tool

| Factor | CloudQuery | Steampipe | AWS Config | Standalone |
|--------|-----------|-----------|------------|------------|
| Setup effort | Config file + sync | Plugin install | Already deployed | None |
| Best for | CI/CD pipelines | Ad-hoc queries | Zero new tooling | Quick start |
| AWS coverage | 300+ resource types | 150+ tables | 380+ types | Per-service jq |
| Multi-cloud | AWS, GCP, Azure, K8s | 150+ plugins | AWS only | AWS only |
| Credential model | Service account | Interactive or service | IAM role | CLI profile |
| Historical snapshots | Database retention | Point-in-time | S3 delivery channel | Manual |

Pick the tool your team already knows. Stave doesn't care how you
produce obs.v0.1 — only that it conforms to the schema.

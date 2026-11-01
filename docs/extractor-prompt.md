# Extractor Overview

> **Extractors convert raw AWS CLI JSON into obs.v0.1 observations.**
> All extractor logic lives in the Lean 4 project (`iam-explainer/Stave/Extract/`).
> Convert first, then evaluate with `stave apply --observations`.

## Canonical implementation

All extractor logic lives in the `iam-explainer` Lean 4 project under
`Stave/Extract/`. The implementation is formally verified — zero sorry,
all proofs checked at compile time.

### Module map

| Module | What it does | Transforms |
|---|---|---|
| `Asset.lean` | Core `ObsAsset` type, JSON helpers | — |
| `S3.lean` | S3 bucket transforms | buckets, encryption, public access block, tags |
| `CloudTrail.lean` | CloudTrail trail transform | trails |
| `KMS.lean` | KMS key transforms | keys, rotation, key policy |
| `EC2.lean` | EC2 transforms | volumes, instances, security groups |
| `IAM.lean` | IAM transforms | roles, users, groups, password policy, attached policies, tags, inline policies |
| `Misc.lean` | CloudWatch, Config, Lambda, OpenSearch | alarms, recorders, functions, domains |
| `SupplyChain.lean` | OIDC federation trust analysis | [details](extractor-supply-chain.md) |
| `CrossEnv.lean` | Cross-account trust BFS | [details](extractor-cross-env.md) |
| `Escalation.lean` | Privilege escalation pattern matching | [details](extractor-escalation.md) |
| `Exfiltration.lean` | Data exfiltration reverse reachability | [details](extractor-exfiltration.md) |
| `Reachability.lean` | Anonymous principal BFS | [details](extractor-reachability.md) |

### Architecture

Every extractor is a pure function: `Json → List ObsAsset`. No IO,
no API calls, no side effects. The input is already-collected AWS CLI
or Steampipe JSON. The output conforms to the `obs.v0.1` schema.

```
AWS CLI / Steampipe JSON  →  Lean 4 extractor  →  obs.v0.1 JSON  →  stave apply
```

The 24 basic transforms (S3 through Misc) are 1:1 equivalents of the
Go jq filters in `stave/internal/adapters/aws/transform/filters/`.
The 5 analysis extractors (SupplyChain through Reachability) implement
graph algorithms that the basic transforms cannot express.

## The obs.v0.1 contract

All extractors produce the same JSON shape. Stave evaluates the same
controls regardless of how the observations were created.

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-04-12T00:00:00Z",
  "assets": [
    {
      "id": "unique-resource-identifier",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": { }
    }
  ]
}
```

## Writing a custom extractor

If you need a data source or resource type the built-in extractors
don't cover, write a function that produces `List ObsAsset` and
serialize to the schema above. Any language works — the contract is
the only coupling point.

### Using Steampipe

Steampipe exposes cloud APIs as SQL tables. Query, pipe through `jq`,
produce obs.v0.1 directly:

```bash
steampipe query --output json \
  "SELECT name, region, versioning_enabled, server_side_encryption_configuration,
          logging, acl, policy, public_access_block_configuration
   FROM aws_s3_bucket" \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
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
    }' > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json
```

### Using CloudQuery

CloudQuery syncs cloud configuration to a local database on a
schedule. Query the synced data and transform to obs.v0.1 without
additional API calls:

```bash
cloudquery sync aws-config.yml

sqlite3 -json cloudquery.db \
  "SELECT name, versioning_status, server_side_encryption_configuration,
          logging_target_bucket, block_public_acls, block_public_policy,
          ignore_public_acls, restrict_public_buckets
   FROM aws_s3_buckets" \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
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
    }' > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json
```

### Using AWS Config

If your organization already has AWS Config enabled, export
configuration snapshots directly:

```bash
aws configservice select-resource-config \
  --expression "SELECT resourceId, resourceType, configuration
                WHERE resourceType = 'AWS::S3::Bucket'" \
  --output json \
  | jq '{
      schema_version: "obs.v0.1",
      captured_at: (now | todate),
      assets: [.Results[] | fromjson | {
        id: .resourceId,
        type: "aws_s3_bucket",
        vendor: "aws",
        properties: {
          storage: {
            kind: "bucket",
            name: .resourceId
          }
        }
      }]
    }' > observations/$(date -u +%Y-%m-%dT%H%M%SZ).json
```

### Choosing an extraction tool

| Tool | Best for | Multi-cloud |
|---|---|---|
| **Lean 4 extractors** | Formal verification, analysis algorithms | AWS (extensible) |
| **Steampipe** | Ad-hoc queries, 150+ plugins | AWS, GCP, Azure, K8s |
| **CloudQuery** | Scheduled pipelines, historical snapshots | AWS, GCP, Azure, K8s |
| **AWS Config** | Teams already using Config | AWS only |
| **Custom script** | Niche sources, exact field control | Anything |

All paths produce the same obs.v0.1 JSON. Stave evaluates the same
controls regardless of how the observations were created.

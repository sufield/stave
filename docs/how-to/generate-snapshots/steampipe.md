# How to Generate Snapshots with Steampipe

Produce Stave-conforming observation snapshots using Steampipe SQL queries against AWS.

---

## Prerequisites

- [Steampipe](https://steampipe.io/downloads) installed
- [AWS plugin](https://hub.steampipe.io/plugins/turbot/aws) installed and configured
- `jq` installed for JSON transformation

## S3 Bucket Snapshot

```sql
select
  arn as id,
  'aws_s3_bucket' as type,
  'aws' as vendor,
  json_build_object(
    'storage', json_build_object(
      'kind', 'bucket',
      'name', name,
      'controls', json_build_object(
        'public_access_fully_blocked',
          block_public_acls and ignore_public_acls
          and block_public_policy and restrict_public_buckets,
        'account_public_access_fully_blocked',
          account_level_public_access_block is not null,
        'public_access_block', json_build_object(
          'block_public_acls', block_public_acls,
          'ignore_public_acls', ignore_public_acls,
          'block_public_policy', block_public_policy,
          'restrict_public_buckets', restrict_public_buckets
        )
      ),
      'encryption', json_build_object(
        'algorithm', coalesce(
          server_side_encryption_configuration->>'SSEAlgorithm', 'none'),
        'kms_key_id', server_side_encryption_configuration->>'KMSMasterKeyID'
      ),
      'versioning', json_build_object(
        'enabled', versioning_enabled
      ),
      'logging', json_build_object(
        'enabled', logging is not null and logging->>'TargetBucket' is not null
      ),
      'tags', tags
    )
  ) as properties
from aws_s3_bucket;
```

## Field Mapping: S3

| Steampipe Column | Stave Property Path |
|------------------|---------------------|
| `block_public_acls` | `properties.storage.controls.public_access_block.block_public_acls` |
| `block_public_policy` | `properties.storage.controls.public_access_block.block_public_policy` |
| `server_side_encryption_configuration` | `properties.storage.encryption.algorithm` |
| `versioning_enabled` | `properties.storage.versioning.enabled` |
| `logging` | `properties.storage.logging.enabled` |
| `tags` | `properties.storage.tags` |

## EC2 Instance Snapshot

```sql
select
  instance_id as id,
  'aws_ec2_instance' as type,
  'aws' as vendor,
  json_build_object(
    'compute', json_build_object(
      'kind', 'instance',
      'network', json_build_object(
        'has_public_ip', public_ip_address is not null,
        'imdsv2_required', metadata_options->>'HttpTokens' = 'required'
      ),
      'monitoring', json_build_object(
        'detailed_enabled', monitoring_state = 'enabled'
      ),
      'iam_instance_profile', json_build_object(
        'attached', iam_instance_profile is not null
      ),
      'tags', tags
    )
  ) as properties
from aws_ec2_instance;
```

## Field Mapping: EC2

| Steampipe Column | Stave Property Path |
|------------------|---------------------|
| `metadata_options->>'HttpTokens'` | `properties.compute.network.imdsv2_required` |
| `public_ip_address` | `properties.compute.network.has_public_ip` |
| `monitoring_state` | `properties.compute.monitoring.detailed_enabled` |
| `iam_instance_profile` | `properties.compute.iam_instance_profile.attached` |

## RDS Instance Snapshot

```sql
select
  arn as id,
  'aws_rds_instance' as type,
  'aws' as vendor,
  json_build_object(
    'database', json_build_object(
      'kind', 'rds_instance',
      'publicly_accessible', publicly_accessible,
      'storage_encrypted', storage_encrypted,
      'deletion_protection', deletion_protection,
      'multi_az', multi_az,
      'auto_minor_version_upgrade', auto_minor_version_upgrade,
      'backup_retention_period', backup_retention_period
    )
  ) as properties
from aws_rds_db_instance;
```

## Wrapper Script

```bash
#!/bin/bash
# generate-snapshot.sh — produces a complete multi-service snapshot
set -euo pipefail

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT="snapshot-${TIMESTAMP}.json"

echo '{"schema_version":"obs.v0.1","snapshots":[{"schema_version":"obs.v0.1","source":"deployed","captured_at":"'$TIMESTAMP'","generated_by":{"source_type":"steampipe","tool":"steampipe","tool_version":"0.1.0"},"assets":['

steampipe query --output json "$(cat queries/s3.sql)" | jq -c '.[]' | paste -sd,
echo ','
steampipe query --output json "$(cat queries/ec2.sql)" | jq -c '.[]' | paste -sd,
echo ','
steampipe query --output json "$(cat queries/rds.sql)" | jq -c '.[]' | paste -sd,

echo ']}]}'
) > "$OUTPUT"

echo "Wrote $OUTPUT"
```

## Daily Cron Setup

```cron
0 3 * * * /opt/stave/generate-snapshot.sh && cd /opt/stave/snapshots && git add . && git commit -m "daily snapshot $(date -u +%Y-%m-%d)"
```

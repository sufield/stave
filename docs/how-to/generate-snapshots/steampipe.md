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

## IAM Role Snapshot

```sql
select
  arn as id,
  'aws_iam_role' as type,
  'aws' as vendor,
  json_build_object(
    'identity', json_build_object(
      'kind', 'role',
      'arn', arn,
      'assume_role_policy', assume_role_policy_document,
      'attached_policies', coalesce(attached_policy_arns, '[]'::jsonb),
      'inline_policies', coalesce(inline_policies, '[]'::jsonb),
      'path', path,
      'tags', tags
    )
  ) as properties
from aws_iam_role;
```

### Field Mapping: IAM Role

| Steampipe Column                   | Stave Property Path                       |
|------------------------------------|-------------------------------------------|
| `arn`                              | `id` and `properties.identity.arn`        |
| `assume_role_policy_document`      | `properties.identity.assume_role_policy`  |
| `attached_policy_arns`             | `properties.identity.attached_policies`   |
| `inline_policies`                  | `properties.identity.inline_policies`     |
| `path`                             | `properties.identity.path`                |
| `tags`                             | `properties.identity.tags`                |

## IAM User Snapshot

```sql
select
  arn as id,
  'aws_iam_user' as type,
  'aws' as vendor,
  json_build_object(
    'identity', json_build_object(
      'kind', 'user',
      'arn', arn,
      'mfa_enabled', mfa_enabled,
      'attached_policies', coalesce(attached_policy_arns, '[]'::jsonb),
      'inline_policies', coalesce(inline_policies, '[]'::jsonb),
      'access_keys', coalesce(access_keys, '[]'::jsonb),
      'password_last_used', password_last_used,
      'tags', tags
    )
  ) as properties
from aws_iam_user;
```

### Field Mapping: IAM User

| Steampipe Column                   | Stave Property Path                       |
|------------------------------------|-------------------------------------------|
| `arn`                              | `id` and `properties.identity.arn`        |
| `mfa_enabled`                      | `properties.identity.mfa_enabled`         |
| `attached_policy_arns`             | `properties.identity.attached_policies`   |
| `inline_policies`                  | `properties.identity.inline_policies`     |
| `access_keys`                      | `properties.identity.access_keys`         |
| `password_last_used`               | `properties.identity.password_last_used`  |

## VPC Security Group Snapshot

```sql
select
  group_id as id,
  'aws_vpc_security_group' as type,
  'aws' as vendor,
  json_build_object(
    'network', json_build_object(
      'kind', 'security_group',
      'group_id', group_id,
      'vpc_id', vpc_id,
      'rules', json_build_object(
        'ingress', coalesce(ip_permissions, '[]'::jsonb),
        'egress', coalesce(ip_permissions_egress, '[]'::jsonb)
      )
    )
  ) as properties
from aws_vpc_security_group;
```

### Field Mapping: VPC Security Group

| Steampipe Column        | Stave Property Path                          |
|-------------------------|----------------------------------------------|
| `group_id`              | `id` and `properties.network.group_id`       |
| `vpc_id`                | `properties.network.vpc_id`                  |
| `ip_permissions`        | `properties.network.rules.ingress`           |
| `ip_permissions_egress` | `properties.network.rules.egress`            |

Each rule entry under `ingress` / `egress` follows the AWS shape and
preserves these nested fields:

| Rule Field                      | Meaning                                    |
|---------------------------------|--------------------------------------------|
| `IpProtocol`                    | Protocol — `tcp`, `udp`, `icmp`, or `-1`   |
| `FromPort` / `ToPort`           | Port range (omitted for protocol `-1`)     |
| `IpRanges[].CidrIp`             | Allowed IPv4 CIDR blocks                   |
| `Ipv6Ranges[].CidrIpv6`         | Allowed IPv6 CIDR blocks                   |
| `UserIdGroupPairs[].GroupId`    | Allowed source security groups             |
| `PrefixListIds[].PrefixListId`  | Allowed source prefix lists                |

Predicates can read these directly via dotted paths
(e.g. `properties.network.rules.ingress[].IpRanges[].CidrIp`).

## GCP Storage Bucket Snapshot

```sql
select
  self_link as id,
  'gcp_storage_bucket' as type,
  'gcp' as vendor,
  json_build_object(
    'storage', json_build_object(
      'kind', 'bucket',
      'name', name,
      'location', location,
      'encryption', json_build_object(
        'algorithm', case when encryption->>'defaultKmsKeyName' is not null
                       then 'CMEK' else 'Google-managed' end,
        'kms_key_id', encryption->>'defaultKmsKeyName'
      ),
      'versioning', json_build_object(
        'enabled', coalesce(versioning_enabled, false)
      ),
      'iam', json_build_object(
        'bindings', coalesce(iam_policy->'bindings', '[]'::jsonb),
        'uniform_bucket_level_access',
          coalesce(iam_configuration->'uniformBucketLevelAccess'->>'enabled', 'false')::boolean
      ),
      'public_access_prevention',
        coalesce(iam_configuration->>'publicAccessPrevention', 'inherited'),
      'labels', labels
    )
  ) as properties
from gcp_storage_bucket;
```

### Field Mapping: GCP Storage Bucket

| Steampipe Column                                     | Stave Property Path                                  |
|------------------------------------------------------|------------------------------------------------------|
| `name`                                               | `properties.storage.name`                            |
| `location`                                           | `properties.storage.location`                        |
| `encryption.defaultKmsKeyName`                       | `properties.storage.encryption.kms_key_id`           |
| `versioning_enabled`                                 | `properties.storage.versioning.enabled`              |
| `iam_policy.bindings`                                | `properties.storage.iam.bindings`                    |
| `iam_configuration.uniformBucketLevelAccess.enabled` | `properties.storage.iam.uniform_bucket_level_access` |
| `iam_configuration.publicAccessPrevention`           | `properties.storage.public_access_prevention`        |

## Azure Storage Blob Container Snapshot

```sql
select
  id as id,
  'azure_storage_blob_container' as type,
  'azure' as vendor,
  json_build_object(
    'storage', json_build_object(
      'kind', 'blob_container',
      'name', name,
      'storage_account', storage_account_name,
      'public_access', coalesce(public_access, 'none'),
      'encryption', json_build_object(
        'algorithm', 'AES-256',
        'key_source', encryption_key_source
      ),
      'immutability_policy', json_build_object(
        'enabled', immutability_policy is not null
      ),
      'has_legal_hold', coalesce(has_legal_hold, false),
      'metadata', metadata
    )
  ) as properties
from azure_storage_container;
```

### Field Mapping: Azure Storage Blob Container

| Steampipe Column          | Stave Property Path                                 |
|---------------------------|-----------------------------------------------------|
| `name`                    | `properties.storage.name`                           |
| `storage_account_name`    | `properties.storage.storage_account`                |
| `public_access`           | `properties.storage.public_access`                  |
| `encryption_key_source`   | `properties.storage.encryption.key_source`          |
| `immutability_policy`     | `properties.storage.immutability_policy.enabled`    |
| `has_legal_hold`          | `properties.storage.has_legal_hold`                 |

## Property Path Discovery

Once a snapshot is generated, use `forge paths` to enumerate every
JSON property the snapshot exposes — that's the definitive list of
expressions a control predicate can use:

```bash
# 1. Generate a snapshot
./generate-snapshot.sh > observations/sample.json

# 2. List every available property path
stave forge paths --in observations/sample.json

# Sample output:
#   properties.storage.name
#   properties.storage.versioning.enabled
#   properties.storage.encryption.algorithm
#   properties.storage.encryption.kms_key_id
#   properties.storage.controls.public_access_block.block_public_acls
#   ...

# 3. Author a control referencing those paths.
stave forge new
```

The workflow is iterative: extend the SQL → regenerate the snapshot
→ rerun `forge paths` to confirm the new field appeared at the
expected path → write the predicate against that path. The same
discovery loop applies to any extraction pipeline (Steampipe,
CloudQuery, custom scripts) — `forge paths` reads the snapshot, so
the source doesn't matter.

## Wrapper Script

```bash
#!/bin/bash
# generate-snapshot.sh — produces a complete multi-service snapshot
#
# Usage:
#   ./generate-snapshot.sh                  # all services
#   ./generate-snapshot.sh --services s3,ec2  # subset
#   ./generate-snapshot.sh --queries-dir /opt/stave/queries
#
# Reads SQL templates from a queries/ directory; one .sql file per
# service (s3.sql, ec2.sql, rds.sql, iam_role.sql, iam_user.sql,
# vpc_security_group.sql, gcp_storage_bucket.sql,
# azure_storage_blob_container.sql). Each query must return rows
# with id, type, vendor, properties columns; the wrapper joins them
# into a single obs.v0.1 snapshot.
set -euo pipefail

QUERIES_DIR="queries"
SERVICES=""

# Parse flags.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --services)        SERVICES="$2"; shift 2 ;;
    --queries-dir)     QUERIES_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

# Default service list when --services is not supplied: every .sql
# file under QUERIES_DIR. The order from `ls` is alphabetical, which
# is fine for output determinism.
if [[ -z "$SERVICES" ]]; then
  SERVICES=$(ls "$QUERIES_DIR"/*.sql 2>/dev/null \
    | xargs -n1 basename \
    | sed 's/\.sql$//' \
    | paste -sd,)
fi

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT="snapshot-${TIMESTAMP}.json"

# Build the assets array by concatenating the result-row arrays from
# every selected query. jq -s '. | add' merges them into one array.
TMP_PARTS=$(mktemp)
trap "rm -f $TMP_PARTS" EXIT

IFS=',' read -ra SVC_LIST <<< "$SERVICES"
for svc in "${SVC_LIST[@]}"; do
  query_file="$QUERIES_DIR/${svc}.sql"
  if [[ ! -f "$query_file" ]]; then
    echo "warning: no query for service $svc at $query_file" >&2
    continue
  fi
  steampipe query --output json "$(cat "$query_file")" >> "$TMP_PARTS"
done

ASSETS=$(jq -s 'add // []' "$TMP_PARTS")

jq -n \
  --arg ts "$TIMESTAMP" \
  --argjson assets "$ASSETS" \
  '{
    schema_version: "obs.v0.1",
    generated_by: {
      source_type: "steampipe",
      tool: "steampipe",
      tool_version: "0.21.0"
    },
    captured_at: $ts,
    assets: $assets
  }' > "$OUTPUT"

echo "Wrote $OUTPUT (services: $SERVICES)"
```

The script now uses `jq -n` to assemble a strictly-valid `obs.v0.1`
document — no manual JSON concatenation, no concerns about trailing
commas. Every service's query file is independent; adding a new
service is a `cp` of an existing one and a one-word edit.

## Daily Cron Setup

```cron
0 3 * * * /opt/stave/generate-snapshot.sh && cd /opt/stave/snapshots && git add . && git commit -m "daily snapshot $(date -u +%Y-%m-%d)"
```

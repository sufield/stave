# Database Domain

Contract fields for AWS RDS observations. Namespace prefix: `database.*`.
DynamoDB and other database kinds use the shared `database.*` namespace
discriminated by `database.kind` — see [misc.md](misc.md) for the
compliance-expansion table.

Part of the [observation contract](README.md).

## RDS Domain (database.*)

### RDS Instance (`aws_rds_instance`)

| Field | Type | Description |
|-------|------|-------------|
| `database.kind` | string | `"instance"` — discriminator |
| `database.encryption.storage_encrypted` | bool | Storage encryption enabled |
| `database.encryption.kms_key_id` | string | KMS key ARN (if applicable) |
| `database.access.publicly_accessible` | bool | Instance has public endpoint |
| `database.access.multi_az` | bool | Multi-AZ deployment enabled |
| `database.backup.enabled` | bool | Automated backups enabled |
| `database.backup.retention_days` | integer | Backup retention period in days |
| `database.logging.audit_log_enabled` | bool | CloudWatch log exports enabled |
| `database.logging.log_types` | array | Exported log types (audit, error, slowquery) |

---

## DynamoDB / DAX (database.dynamodb.*)

DynamoDB tables use `database.kind = "table"` and the `database.*`
shared fields above (encryption.sse_type, pitr_enabled, backup.*).
DAX clusters use `database.kind = "dynamodb_dax_cluster"` and the
DAX-specific fields below. The relationship between a table and its
DAX cluster surfaces through `database.dynamodb.has_dax` on the
table.

### DynamoDB Table (`aws_dynamodb_table`) extensions

| Field | Type | Description |
|-------|------|-------------|
| `database.dynamodb.has_dax` | bool | The table is paired with a DAX cluster |
| `database.dynamodb.encryption_mismatch` | bool | The table and its DAX cluster have inconsistent encryption posture |

### DAX Cluster (`aws_dynamodb_dax_cluster`)

| Field | Type | Description |
|-------|------|-------------|
| `database.kind` | string | `"dynamodb_dax_cluster"` — discriminator |
| `database.dynamodb.dax.cluster_name` | string | Cluster name |
| `database.dynamodb.dax.cluster_arn` | string | Cluster ARN |
| `database.dynamodb.dax.encrypted_at_rest` | bool | At-rest encryption enabled (cluster-creation-time only) |
| `database.dynamodb.dax.tls_enabled` | bool | TLS enforced for client connections |
| `database.dynamodb.dax.node_count` | int | Number of nodes in the cluster |
| `database.dynamodb.dax.single_node` | bool | Cluster has only one node |
| `database.dynamodb.dax.node_type` | string | Cluster node instance type |
| `database.dynamodb.dax.sg_ids` | []string | Security groups attached to the cluster |
| `database.dynamodb.dax.sg_allows_broad` | bool | An SG accepts inbound from a broad CIDR (whole VPC or 0.0.0.0/0) |
| `database.dynamodb.dax.sg_source_cidrs` | []string | Source CIDRs in the SG inbound rules |
| `database.dynamodb.dax.role_arn` | string | DAX service role IAM ARN |
| `database.dynamodb.dax.role_has_wildcard` | bool | The role's policy uses dynamodb:* or wildcard resources |
| `database.dynamodb.dax.role_actions` | []string | Granted DynamoDB actions |
| `database.dynamodb.dax.role_resources` | []string | Granted DynamoDB resource ARNs |
| `database.dynamodb.dax.subnet_group` | string | Subnet group name |
| `database.dynamodb.dax.has_ghost_role` | bool | The service role IAM ARN has been deleted |
| `database.dynamodb.dax.has_ghost_subnet` | bool | The subnet group references a deleted subnet |
| `database.dynamodb.dax.has_ghost_sg` | bool | The cluster references a deleted security group |
| `database.dynamodb.dax.ghost_sg_ids` | []string | Specific deleted SG IDs (when `has_ghost_sg` is true) |

---


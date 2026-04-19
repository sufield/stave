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


# Compute Domain

Contract fields for AWS EC2 instances, EBS snapshots, container workloads,
and IMDSv2 configuration. Namespace prefix: `compute.*`. Lambda function
URL fields under `compute.function_url.*` are documented in
[cors.md](cors.md) alongside the cross-service CORS namespace.

Part of the [observation contract](README.md).

## EC2 Domain (compute.*)

### EC2 Instance (`aws_ec2_instance`)

| Field | Type | Description |
|-------|------|-------------|
| `compute.kind` | string | `"instance"` — discriminator |
| `compute.encryption.ebs_encrypted` | bool | All attached EBS volumes encrypted |
| `compute.network.has_public_ip` | bool | Instance has a public IP address |
| `compute.network.imdsv2_required` | bool | IMDSv2 HttpTokens set to required |
| `compute.network.imds_hop_limit` | int | `HttpPutResponseHopLimit` (default 2; set to 1 to block container bridge-network bypass) |
| `compute.containers.present` | bool | Instance runs at least one container workload (Docker, ECS task, EKS pod) |
| `compute.containers.has_host_network` | bool | Any container uses host network mode (bypasses IMDS hop limit entirely) |
| `compute.containers.has_bridge_network` | bool | Any container uses bridge network mode (reaches IMDS when hop limit > 1) |

### EBS Snapshot (`aws_ebs_snapshot`)

| Field | Type | Description |
|-------|------|-------------|
| `compute.kind` | string | `"snapshot"` — discriminator |
| `compute.encryption.encrypted` | bool | Snapshot is encrypted |

---

## ECS Container Workload Domain (container.*)

Per-container task-definition fields, sourced from the
`DescribeTaskDefinition` API. Each container in a task definition is
represented as one asset of type `aws_ecs_task_definition_container`
(legacy: `task_definition`); the discriminator field
`container.kind` is `"task_definition"`.

### ECS Task Definition Container (`aws_ecs_task_definition_container`)

| Field | Type | Description |
|-------|------|-------------|
| `container.kind` | string | `"task_definition"` — discriminator |
| `container.privileged.enabled` | bool | Container has `privileged: true` |
| `container.user.is_root` | bool | Container runs as root (UID 0, user "root", or unspecified) |
| `container.network.host_mode` | bool | Task uses `networkMode: host` |
| `container.security.has_dangerous_capabilities` | bool | Adds SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_RAWIO/DAC_OVERRIDE/NET_RAW or fails to drop unnecessary capabilities |
| `container.logging.driver_configured` | bool | A `logConfiguration` log driver is set |
| `container.logging.has_ghost_log_group` | bool | The awslogs log group does not exist |
| `container.logging.log_group` | string | The CloudWatch log group name (when driver is awslogs) |
| `container.filesystem.readonly_root` | bool | `readonlyRootFilesystem: true` |
| `container.mount.has_dangerous_mount` | bool | Mounts a sensitive host path (Docker socket / /proc / /sys / /dev / /) |
| `container.mount.dangerous_paths` | []string | Specific dangerous host paths mounted |
| `container.resources.has_memory_limit` | bool | Either `memory` or `memoryReservation` is set |
| `container.resources.memory_limit_mib` | int | Hard memory limit in MiB (0 if not set) |
| `container.resources.memory_reservation_mib` | int | Soft memory reservation in MiB (0 if not set) |
| `container.health.has_health_check` | bool | A `healthCheck` block is configured |
| `container.health.health_check_type` | string | Health check command form (typically `CMD-SHELL` or `CMD`) |
| `container.image.has_ghost_reference` | bool | The container image was deleted from the registry |
| `container.secrets.has_ghost_reference` | bool | A Secrets Manager secret referenced by valueFrom has been deleted |
| `container.secrets.exec_role_can_access` | bool | Execution role has IAM permission for every secret/parameter referenced |
| `container.ssm_parameters.has_ghost_reference` | bool | An SSM parameter referenced by valueFrom has been deleted |
| `container.ssm_parameters.has_insecure_string_type` | bool | At least one referenced SSM parameter is stored as String, not SecureString |
| `container.execution_role.is_ghost` | bool | The execution role IAM ARN does not exist |
| `container.task_role.is_ghost` | bool | The task role IAM ARN does not exist |

### ECS Service Network Configuration (`aws_ecs_service`)

| Field | Type | Description |
|-------|------|-------------|
| `container.kind` | string | `"ecs_service"` — discriminator |
| `container.network.has_ghost_subnet` | bool | Service references a deleted subnet (awsvpc mode) |
| `container.network.ghost_subnet_ids` | []string | Specific deleted subnet IDs |

### ECS Task Definition Family (`aws_ecs_task_definition_family`)

The family aggregates all revisions of a task definition.

| Field | Type | Description |
|-------|------|-------------|
| `container.kind` | string | `"task_definition_family"` — discriminator |
| `container.revision_history.stale_credential_revision_count` | int | Number of inactive revisions whose env vars still contain plaintext credentials |
| `container.revision_history.stale_credential_revisions` | []int | Revision numbers whose env vars contain plaintext credentials |

### ECR Repository (`aws_ecr_repository`)

ECR repositories use the `container_registry.*` namespace; the
discriminator field `container_registry.kind` is `"repository"`.

| Field | Type | Description |
|-------|------|-------------|
| `container_registry.kind` | string | `"repository"` — discriminator |
| `container_registry.access.public` | bool | The repository allows public pull |
| `container_registry.scanning.enabled` | bool | Image scanning is configured (any mode) |
| `container_registry.scanning.enhanced` | bool | Scanning uses Amazon Inspector (ENHANCED) rather than Clair-based (BASIC) |
| `container_registry.scanning.scan_type` | string | `"BASIC"` or `"ENHANCED"` |
| `container_registry.signing.enforced` | bool | Image signing verification is in enforce mode |
| `container_registry.has_lifecycle_policy` | bool | A lifecycle policy is attached |
| `container_registry.image_tag_mutability` | string | `"MUTABLE"` or `"IMMUTABLE"` |
| `container_registry.policy.has_broad_cross_account` | bool | Repository policy grants cross-account access without specific account IDs or `aws:PrincipalOrgID` |
| `container_registry.encryption.uses_cmk` | bool | Repository is encrypted with a customer-managed KMS key (rather than AWS-owned default) |
| `container_registry.encryption.encryption_type` | string | `"AES256"` (default) or `"KMS"` |
| `container_registry.encryption.kms_key_arn` | string | The customer-managed KMS key ARN (when `uses_cmk` is true) |
| `container_registry.findings.has_unresolved_critical_or_high` | bool | CRITICAL or HIGH findings outstanding past remediation window (14d / 30d) |
| `container_registry.findings.critical_count` | int | Outstanding CRITICAL findings count |
| `container_registry.findings.high_count` | int | Outstanding HIGH findings count |
| `container_registry.findings.oldest_finding_days` | int | Age of the oldest unresolved CRITICAL or HIGH finding |

---


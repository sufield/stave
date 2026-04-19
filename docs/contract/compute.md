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


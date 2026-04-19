# Network Domain

Contract fields for AWS VPC and security group observations. Namespace
prefix: `network.*`.

Part of the [observation contract](README.md).

## VPC Domain (network.*)

### VPC (`aws_vpc`)

| Field | Type | Description |
|-------|------|-------------|
| `network.kind` | string | `"vpc"` — discriminator |
| `network.flow_log.enabled` | bool | VPC flow logging enabled |
| `network.flow_log.encrypted` | bool | Flow logs encrypted at destination |
| `network.flow_log.destination_type` | string | `cloud-watch-logs` or `s3` |

### Security Group (`aws_security_group`)

| Field | Type | Description |
|-------|------|-------------|
| `network.kind` | string | `"security_group"` — discriminator |
| `network.security_group.is_default` | bool | Is the VPC default security group |
| `network.security_group.has_rules` | bool | Has any ingress or egress rules |
| `network.security_group.has_unrestricted_ingress` | bool | 0.0.0.0/0 in any ingress rule |

---


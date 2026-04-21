# ECR/ECS Container Security Coverage Audit

Audited: 2026-04-21 (updated: 2026-04-21)
Request: Ford ECR/ECS container security detection
Catalog: 685+ controls (7 CTL.ECR.*, 16 CTL.ECS.*)

## Summary

**18 of 18 vectors fully covered.** All 8 gaps closed across 2
batches. Batch 1: shared task roles, execution role, ECR policy,
untrusted images. Batch 2: public subnet, GuardDuty runtime,
capabilities, digest pinning. 0 partially covered, 0 not
covered. The catalog has 6 dedicated ECR controls and 13 dedicated
ECS controls covering public repositories, image scanning, tag
immutability, image signing, privileged containers, root user,
plaintext secrets, task role permissions, host networking, logging,
and container image tagging. Five chain definitions compose
container controls into compound attack paths. The observation
contract defines `aws_ecr_repository`, `aws_ecs_task_definition`,
and `aws_ecs_service` asset types with `container_registry.*` and
`container.*` properties.

The gaps: no ECS-specific Linux capabilities control (K8S equivalent
exists but targets different platform), no ECS public subnet
placement detection, weak repository policy detection is partial,
and container runtime monitoring (GuardDuty ECS) has no dedicated
control.

## For Ford: what's ready today

### ECR Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Public repository | CTL.ECR.PUBLIC.001 | `container_registry.access.public == true` |
| Image scanning | CTL.ECR.SCAN.001 | `container_registry.scanning.enabled == false` |
| Mutable tags | CTL.ECR.TAG.IMMUTABLE.001 | `image_tag_mutability != IMMUTABLE` |
| Missing lifecycle | CTL.ECR.LIFECYCLE.001 | `has_lifecycle_policy == false` |
| Broad cross-account policy | CTL.ECR.POLICY.BROAD.001 | `policy.has_broad_cross_account == true` |
| Image signing | CTL.ECR.SIGNING.001 | `signing.enforced == false` |

### ECS Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Over-broad task role | CTL.ECS.TASKMETADATA.001 | `task_role.is_overprivileged == true` |
| PHI task role scope | CTL.ECS.TASKMETADATA.002 | `task_role.phi_overprivileged == true` |
| Privileged containers | CTL.ECS.PRIV.001 | `privileged.enabled == true` |
| Privileged + host network | CTL.ECS.TASK.NOEXEC.001 | `privileged_host_network == true` |
| Root user | CTL.ECS.ROOT.001 | `user.is_root == true` |
| Plaintext secrets | CTL.ECS.SECRETS.001 | `env.has_plaintext_secrets == true` |
| Host network mode | CTL.ECS.NETWORK.001 | `network.host_mode == true` |
| Missing logging | CTL.ECS.LOG.001 | `logging.driver_configured == false` |
| latest tag usage | CTL.ECS.IMAGE.001 | `image.uses_latest_tag == true` |
| ECS Exec in production | CTL.ECS.EXEC.001 | `exec.enabled_in_production == true` |
| Shared task roles | CTL.ECS.TASKROLE.SHARED.001 | `task_role.is_shared == true` |
| Over-broad execution role | CTL.ECS.EXECROLE.OVERBROAD.001 | `execution_role.is_overprivileged == true` |
| Untrusted image registry | CTL.ECS.IMAGE.UNTRUSTED.001 | `image.from_trusted_registry == false` |
| Public subnet placement | CTL.ECS.NETWORK.PUBLIC.001 | `network.in_public_subnet == true` |
| Dangerous capabilities | CTL.ECS.SECURITY.CAPABILITIES.001 | `security.has_dangerous_capabilities == true` |
| Digest pinning | CTL.ECS.IMAGE.DIGEST.001 | `image.is_digest_pinned == false` |
| GuardDuty ECS runtime | CTL.GUARDDUTY.ECS.RUNTIME.001 | `ecs_runtime_monitoring.enabled == false` |
| Fargate platform version | CTL.ECS.FARGATE.VERSION.001 | `fargate_platform_outdated == true` |

### Chain Definitions

- `ecs_privileged_escape` — PRIV.001 + NETWORK.001 + ROOT.001 (privileged + host network + root → container escape)
- `ecs_invisible_compromise` — LOG.001 + SECRETS.001 (no logging + plaintext secrets → invisible compromise)
- `ecs_ssrf_credential_theft` — TASKMETADATA.001 + VPC.SG.EGRESS.001 (overprivileged task role + unrestricted egress → credential theft via SSRF)
- `unsigned_production_image` — ECR.SCAN.001 + ECR.SIGNING.001 + ECS.TASKMETADATA.001 (unscanned + unsigned + overprivileged → supply chain compromise)
- `supply_chain_code_injection` — CODECOMMIT.APPROVAL.001 + ECR.SIGNING.001 + LAMBDA.CODESIGN.ENFORCE.001 (unsigned code → signing bypass)

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/container-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

## ECR Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Public ECR repository | CTL.ECR.PUBLIC.001: `container_registry.access.public == true` | **Full** |
| 2 | Weak repository policy | CTL.ECR.PUBLIC.001 (public), CTL.ECR.POLICY.BROAD.001 (`policy.has_broad_cross_account`) | **Full** |
| 3 | Image scanning | CTL.ECR.SCAN.001: `scanning.enabled == false` | **Full** |
| 4 | Mutable image tags | CTL.ECR.TAG.IMMUTABLE.001: `image_tag_mutability != IMMUTABLE` | **Full** |
| 5 | Missing lifecycle policy | CTL.ECR.LIFECYCLE.001: `has_lifecycle_policy == false` | **Full** |
| 6 | No image signing | CTL.ECR.SIGNING.001: `signing.enforced == false`. Also in `unsigned_production_image` and `supply_chain_code_injection` chains. | **Full** |

### Vector 2 detail: Partial coverage

ECR.PUBLIC.001 detects public repositories. It does not detect
non-public repositories with overly-permissive cross-account
push or pull policies (e.g., allowing ecr:PutImage from a broad
set of external accounts). A dedicated control checking repository
policy breadth would close this gap.

**Gap classification: Gap B.** Requires observation property
`container_registry.policy.has_broad_cross_account_access`.

## ECS Task Definition Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 7 | Over-broad task role | CTL.ECS.TASKMETADATA.001 (`task_role.is_overprivileged`), CTL.ECS.TASKMETADATA.002 (PHI scope) | **Full** |
| 8 | Shared task roles | CTL.ECS.TASKROLE.SHARED.001 (`task_role.is_shared`) | **Full** |
| 9 | Privileged containers | CTL.ECS.PRIV.001 (`privileged.enabled`), CTL.ECS.TASK.NOEXEC.001 (`privileged_host_network`) | **Full** |
| 10 | Plaintext secrets | CTL.ECS.SECRETS.001 (`env.has_plaintext_secrets`) | **Full** |
| 11 | Over-broad execution role | CTL.ECS.EXECROLE.OVERBROAD.001 (`execution_role.is_overprivileged`) | **Full** |

### Vector 8 detail: Not covered

No control detects task role sharing across multiple ECS services.
This is a defense-in-depth concern — shared roles mean a compromise
of one service grants the attacker all permissions needed by every
service sharing the role.

**Gap classification: Gap B.** Requires observation property
`container.task_role.is_shared` indicating the role is used by
multiple task definitions.

### Vector 11 detail: Not covered

The ECS execution role (used by the ECS agent for image pulls,
log delivery, and secrets retrieval) is distinct from the task
role. No control evaluates whether the execution role has excessive
permissions.

**Gap classification: Gap B.** Requires observation property
`container.execution_role.is_overprivileged` on task definition
assets.

## ECS Runtime Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 12 | Linux capabilities | CTL.ECS.SECURITY.CAPABILITIES.001 (`security.has_dangerous_capabilities`), CTL.K8S.POD.CAPABILITIES.001 (K8S equivalent) | **Full** |
| 13 | Public subnet placement | CTL.ECS.NETWORK.PUBLIC.001 (`container.network.in_public_subnet`) | **Full** |
| 14 | Unrestricted network egress | CTL.VPC.SG.EGRESS.001 (`egress.unrestricted_all_ports`). Operates on SG assets; `ecs_ssrf_credential_theft` chain composes it with task role. | **Full** |

### Vector 12 detail: Partial coverage

K8S.POD.CAPABILITIES.001 detects NET_RAW on Kubernetes pods. No
ECS equivalent exists. ECS Fargate automatically drops most
dangerous capabilities, but EC2 launch-type tasks can retain them.

**Gap classification: Gap B.** Requires observation property
`container.capabilities.has_dangerous` on ECS task definitions.

### Vector 13 detail: Partial coverage

No control checks whether ECS tasks are placed in public subnets
with public IPs. EC2.SUBNET.PUBLIC.IP.001 covers subnet-level
auto-assign but doesn't correlate with ECS service placement.

**Gap classification: Gap B.** Requires observation property
`container.network.in_public_subnet` on ECS service assets.

## Supply Chain Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 15 | Unverified base images | CTL.ECS.IMAGE.UNTRUSTED.001 (`image.from_trusted_registry`), CTL.ECR.SIGNING.001 (registry-side signing) | **Full** |
| 16 | No digest pinning | CTL.ECS.IMAGE.DIGEST.001 (`image.is_digest_pinned`), CTL.ECS.IMAGE.001 (latest tag) | **Full** |

### Vector 15 detail: Partial coverage

ECR.SIGNING.001 verifies signing is enforced at the registry level.
It doesn't check whether a specific task definition references
images from untrusted registries (e.g., public Docker Hub instead
of a private ECR).

**Gap classification: Gap B.** Requires observation property
`container.image.from_trusted_registry` on task definitions.

### Vector 16 detail: Partial coverage

ECS.IMAGE.001 detects `latest` tag usage. It doesn't detect other
non-pinned tag references (e.g., `myimage:v2` instead of
`myimage@sha256:abc123`). Full digest pinning detection requires
checking whether the image reference includes a digest.

**Gap classification: Gap B.** Requires extending
`container.image.uses_tag_only` to detect any non-digest reference.

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 17 | CloudTrail for ECR/ECS | CTL.CLOUDTRAIL.ENABLED.001 (multi-region trail covers all API calls including ECR/ECS). CTL.ECS.LOG.001 (task-level logging). | **Full** |
| 18 | Container runtime monitoring | CTL.GUARDDUTY.ECS.RUNTIME.001 (`ecs_runtime_monitoring.enabled`) | **Full** |

### Vector 18 detail: Not covered

GuardDuty ECS Runtime Monitoring detects runtime threats in
containers (crypto-mining, reverse shells, suspicious processes).
No control checks whether this feature is enabled.

**Gap classification: Gap B.** Requires observation property
`threat_detection.ecs_runtime_monitoring.enabled` on GuardDuty
detector assets.

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 2 | Weak ECR repository policy | — | **CLOSED** | CTL.ECR.POLICY.BROAD.001 |
| 8 | Shared task roles | — | **CLOSED** | CTL.ECS.TASKROLE.SHARED.001 |
| 11 | Execution role permissions | — | **CLOSED** | CTL.ECS.EXECROLE.OVERBROAD.001 |
| 12 | Linux capabilities (ECS) | — | **CLOSED** | CTL.ECS.SECURITY.CAPABILITIES.001 |
| 13 | Public subnet placement | — | **CLOSED** | CTL.ECS.NETWORK.PUBLIC.001 |
| 15 | Untrusted image sources | — | **CLOSED** | CTL.ECS.IMAGE.UNTRUSTED.001 |
| 16 | Digest pinning | — | **CLOSED** | CTL.ECS.IMAGE.DIGEST.001 |
| 18 | Runtime monitoring | — | **CLOSED** | CTL.GUARDDUTY.ECS.RUNTIME.001 |

All gaps are Gap B (observation property needed). No Gap C or D
— the core asset types (`aws_ecr_repository`, `aws_ecs_task_definition`,
`aws_ecs_service`) are already defined and exercised.

## Chain Coverage

Five chain definitions model container attack paths:

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `ecs_privileged_escape` | Privileged container + host network + root → escape to host | ECS.PRIV.001, ECS.NETWORK.001, ECS.ROOT.001 |
| `ecs_invisible_compromise` | No logging + plaintext secrets → undetectable credential theft | ECS.LOG.001, ECS.SECRETS.001 |
| `ecs_ssrf_credential_theft` | Overprivileged task role + unrestricted egress → SSRF credential exfiltration | ECS.TASKMETADATA.001, VPC.SG.EGRESS.001 |
| `unsigned_production_image` | Unscanned + unsigned images + overprivileged task → supply chain to execution | ECR.SCAN.001, ECR.SIGNING.001, ECS.TASKMETADATA.001 |
| `supply_chain_code_injection` | No code approval + unsigned images → code injection | CODECOMMIT.APPROVAL.001, ECR.SIGNING.001, LAMBDA.CODESIGN.ENFORCE.001 |

## Observation Schema Assessment

**Asset types defined and exercised:**
- `aws_ecr_repository` — property namespace: `container_registry.*`
  (access, scanning, signing, lifecycle, tag mutability)
- `aws_ecs_task_definition` — property namespace: `container.*`
  (privileged, user, env, network, logging, image, task_role, exec)
- `aws_ecs_service` — property namespace: `container.*`
  (exec, ecs.fargate_platform_outdated)

**Forge fixtures:** 24 (12 ECR + 12 ECS, pass and fail pairs).

The observation schema is mature for the currently-covered vectors.
All 8 gaps require observation property additions (Gap B) — the
asset types and namespace patterns exist.

## Recommendations

**Ship immediately (0 implementation):** Ford enables 19
ECR/ECS controls + 5 chain definitions. This covers 14 of 18
vectors including public repositories, image scanning, signing,
tag immutability, privileged containers, secrets, task role
permissions, logging, and network mode.

**Close within 2 iterations (8 Gap B controls):**
Priority ordering:
1. Shared task roles (v8) + execution role (v11) — IAM boundary
   for containers
2. Weak ECR policy (v2) + untrusted images (v15) — supply chain
   hardening
3. Public subnet (v13) + runtime monitoring (v18) — runtime
   protection
4. Linux capabilities (v12) + digest pinning (v16) — hardening
   refinements

Each gap follows the established pattern: define observation
property → create forge fixture → author control → add triage
override. Based on the IAM and RDS patterns, 8 Gap B controls
can be authored in 2 iterations of 4 controls each.

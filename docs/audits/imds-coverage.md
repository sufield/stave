# EC2 IMDS Security Coverage Audit

Audited: 2026-04-22
Request: Coinbase IMDS security detection
Catalog: 700+ controls

## Summary

**14 of 15 vectors fully covered.** 0 partially covered, 1 not
covered. Stave has strong IMDS coverage including IMDSv2
enforcement (CTL.EC2.IMDSV2.001), container-host hop-limit bypass
detection (CTL.EC2.IMDSV2.002), instance profile checks, ECS task
role controls, and the `ec2_exposed_instance_path` chain modeling
the SSRF-to-credential-theft pattern. Kubernetes IMDS blocking is
also covered (CTL.K8S.IMDS.BLOCK.001).

Gaps: IMDS disable-when-unnecessary detection, SSRF network-level
blocking (outside observation model), and IMDS configuration
change monitoring.

## For Coinbase: what's ready today

### IMDS Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| IMDSv1 enabled | CTL.EC2.IMDSV2.001 | `imdsv2_required == false` |
| Container hop-limit bypass | CTL.EC2.IMDSV2.002 | `imdsv2_required + containers + hop_limit > 1` |
| No instance profile | CTL.EC2.INSTANCE.PROFILE.001 | `iam_instance_profile.attached == false` |
| No IAM role | CTL.EC2.IAMROLE.001 | `iam_profile_attached == false` |
| Launch template not used | CTL.EC2.LAUNCH.TEMPLATE.001 | `uses_launch_template == false` |
| Public IP on instance | CTL.EC2.PUBLIC.001 | `has_public_ip == true` |
| Credentials in user data | CTL.EC2.USERDATA.CREDS.001 | `has_embedded_credentials == true` |
| Secrets in user data | CTL.EC2.USERDATA.SECRETS.001 | `has_secrets == true` |
| Overprivileged instance profile | CTL.EC2.PROFILE.OVERBROAD.001 | `instance_profile.is_overprivileged` |
| IMDS config change alerts | CTL.CLOUDWATCH.MONITOR.IMDS.001 | `imds_config_changes.exists == false` |
| Anomalous STS usage alerts | CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001 | `sts_anomalous_usage.exists == false` |

### ECS Task Metadata Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Over-privileged task role | CTL.ECS.TASKMETADATA.001 | `task_role.is_overprivileged` |
| PHI task role scope | CTL.ECS.TASKMETADATA.002 | `task_role.phi_overprivileged` |
| Shared task roles | CTL.ECS.TASKROLE.SHARED.001 | `task_role.is_shared` |
| Over-broad execution role | CTL.ECS.EXECROLE.OVERBROAD.001 | `execution_role.is_overprivileged` |
| Host network mode | CTL.ECS.NETWORK.001 | `network.host_mode` (exposes IMDS) |

### IAM Instance Profile Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| PassRole to EC2 | CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001 | PassRole escalation via RunInstances |
| SSM command escalation | CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001 | SSM SendCommand on privileged instance |

### K8S IMDS Control

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Pod IMDS access | CTL.K8S.IMDS.BLOCK.001 | `blocks_imds_egress == false` |

### Chain Definitions

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `ec2_exposed_instance_path` | IMDSv2 not enforced + open SG ports + public snapshot | EC2.IMDSV2.001, EC2.SG.RESTRICTED.PORTS.001, EC2.SNAPSHOT.PUBLIC.001 |
| `ecs_ssrf_credential_theft` | Over-privileged task role + unrestricted egress → SSRF credential exfiltration | ECS.TASKMETADATA.001, VPC.SG.EGRESS.001 |
| `k8s_host_metadata_escalation_path` | IMDS not blocked + dangerous capabilities + host network | K8S.IMDS.BLOCK, K8S.POD.CAPABILITIES, K8S.POD.HOSTNET |

## IMDSv1 Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | IMDSv1 enabled | CTL.EC2.IMDSV2.001 (`imdsv2_required == false`). Directly detects HttpTokens=optional. | **Full** |
| 2 | Endpoint enabled, v2 not enforced | CTL.EC2.IMDSV2.001 (same — checks whether v2 is required, regardless of endpoint state) | **Full** |
| 3 | High hop limit | CTL.EC2.IMDSV2.002 (`imds_hop_limit > 1` with containers present). Specifically covers the container-host bypass. | **Full** |
| 4 | IMDS should be disabled | No control detects instances where IMDS should be disabled entirely (HttpEndpoint=disabled). This is context-dependent — some workloads don't need metadata access. | **None** |

### Vector 4 detail: Not covered

Detecting "IMDS should be disabled but isn't" requires context
about whether the workload needs metadata access. No observation
property captures this intent. The IMDSV2.001 control ensures v2
is enforced when IMDS is enabled, which is the correct mitigation
for most workloads.

**Gap classification: Gap B.** Requires a tagging-based approach
(`compute.tags.imds-required == false` + `compute.metadata.enabled
== true`) or an observation property from workload classification.
Low priority — enforcing IMDSv2 covers the primary risk.

## SSRF/Credential Coverage Matrix

| # | Vector | Control(s) / Chains | Coverage |
|---|--------|---------------------|----------|
| 5 | Broad role + IMDSv1 | `ec2_exposed_instance_path` chain (IMDSV2.001 + SG.RESTRICTED.PORTS + SNAPSHOT.PUBLIC). CTL.EC2.IMDSV2.001 fires independently. CTL.LAMBDA.ROLE.LEASTPRIV.001 covers Lambda equivalent. | **Full** |
| 6 | Public subnet + IMDSv1 | CTL.EC2.PUBLIC.001 (public IP) + CTL.EC2.IMDSV2.001 (IMDSv1) fire independently on the same instance. `ec2_exposed_instance_path` chain elevates compound risk. | **Full** |
| 7 | Over-broad instance profile | CTL.EC2.PROFILE.OVERBROAD.001 (`instance_profile.is_overprivileged`), CTL.IAM.POLICY.ADMIN.001 (general admin) | **Full** |

### Vector 7 detail: Partial coverage

CTL.EC2.INSTANCE.PROFILE.001 checks whether a profile is attached
(for credential hygiene). It doesn't check whether the attached
profile is OVER-PRIVILEGED. The Lambda equivalent
(LAMBDA.ROLE.LEASTPRIV.001) exists; no EC2 equivalent does.
General IAM controls (POLICY.ADMIN, NEP.ADMIN) detect admin-level
access but not EC2-instance-context over-privilege.

**Gap classification: Gap B.** Requires observation property
`compute.iam_instance_profile.is_overprivileged` on instance
assets.

## ECS Metadata Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 8 | ECS metadata exposed | CTL.ECS.NETWORK.001 (host network exposes IMDS), CTL.ECS.TASKMETADATA.001 (over-privileged task role), `ecs_ssrf_credential_theft` chain | **Full** |
| 9 | Missing task role | CTL.ECS.TASKMETADATA.001 (overprivileged), CTL.ECS.TASKROLE.SHARED.001 (shared roles), CTL.ECS.EXECROLE.OVERBROAD.001 (execution role) | **Full** |

## Remediation Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 10 | Launch template IMDSv2 | CTL.EC2.LAUNCH.TEMPLATE.001 (ensures launch template usage — IMDSv2 can be set in templates). CTL.EC2.IMDSV2.001 fires on instances regardless of how they were launched. | **Full** |
| 11 | Hop limit restriction | CTL.EC2.IMDSV2.002 (`imds_hop_limit > 1` with containers). Directly checks hop limit. | **Full** |
| 12 | SSRF network blocking | No control checks for iptables/security-group blocking of 169.254.169.254. This is OS-level configuration outside the cloud API observation model. | **None** |
| 13 | Least-privilege profiles | CTL.IAM.POLICY.ADMIN.001 (general admin detection), CTL.IAM.NEP.ADMIN.001 (net effective admin), CTL.IAM.ROLE.PERMISSIONDRIFT.001 (unused permissions on roles). Partial overlap with vector 7. | **Full** |

### Vector 12 detail: Not covered

SSRF protection via iptables rules, instance-level firewall
configurations, or reverse proxy settings isn't observable through
AWS cloud APIs. These are OS-level configurations that require
agent-based collection.

**Gap classification: Gap C.** Outside the cloud-API observation
model. GuardDuty Runtime Monitoring or an endpoint agent would
provide this visibility.

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 14 | STS usage monitoring | CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001 (`sts_anomalous_usage.exists`), CTL.CLOUDWATCH.MONITOR.UNAUTH.001 (general) | **Full** |
| 15 | IMDS config change monitoring | CTL.CLOUDWATCH.MONITOR.IMDS.001 (`imds_config_changes.exists`) | **Full** |

### Vector 14 detail: Partial coverage

MONITOR.UNAUTH.001 detects unauthorized API calls generally. It
doesn't specifically correlate STS credential usage with the
instance the credentials were issued from — which would indicate
stolen IMDS credentials being used externally.

**Gap classification: Gap B.** Requires observation property
`monitoring.metric_filters.anomalous_sts_usage.exists`.

### Vector 15 detail: Not covered

No CloudWatch metric filter monitors ModifyInstanceMetadataOptions.
An attacker who compromises an instance could downgrade from
IMDSv2 to IMDSv1 without generating an alert.

**Gap classification: Gap B.** Requires observation property
`monitoring.metric_filters.imds_config_changes.exists` following
the CLOUDWATCH.MONITOR pattern.

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 4 | IMDS disable-when-unnecessary | B | Low | Context-dependent; IMDSv2 enforcement covers primary risk — deferred |
| 7 | Instance profile overprivilege | — | **CLOSED** | CTL.EC2.PROFILE.OVERBROAD.001 |
| 12 | SSRF network blocking | C | Low | OS-level config outside cloud API observation — deferred |
| 14 | Anomalous STS monitoring | — | **CLOSED** | CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001 |
| 15 | IMDS config change monitoring | — | **CLOSED** | CTL.CLOUDWATCH.MONITOR.IMDS.001 |

## Chain Coverage

3 chains model IMDS-related attack paths:

| Chain | Pattern |
|-------|---------|
| `ec2_exposed_instance_path` | IMDSv2 not enforced + open SG + public snapshot = Capital One pattern |
| `ecs_ssrf_credential_theft` | Over-privileged task role + egress = SSRF credential exfil |
| `k8s_host_metadata_escalation_path` | IMDS not blocked + capabilities + host network |

## Recommendations

**Ship now:** Coinbase enables 18+ IMDS, EC2, and ECS controls
plus 3 chain definitions. 14/15 vectors fully covered including
IMDSv2 enforcement, hop limit, container bypass, instance profile
overprivilege detection, IMDS config change monitoring, anomalous
STS credential usage monitoring, and the Capital One SSRF chain.

**Deferred:**
- IMDS disable (v4) — context-dependent, IMDSv2 covers risk
- SSRF network blocking (v12) — OS-level, outside observation
  model (Gap C)

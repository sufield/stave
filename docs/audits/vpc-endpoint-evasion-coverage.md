# VPC Endpoint Anonymous Access Evasion Coverage Audit

Disclosure: Varonis Threat Labs, "The Invisible Footprint: How
Anonymous S3 Requests Evade AWS Logging" (April 2026). AWS patched
the logging gap; configuration risks that enabled the evasion
remain detectable.

Audited: 2026-04-21 (updated: 2026-04-21)
Catalog: 700+ controls

## Summary

**14 of 15 vectors fully covered.** 0 partially covered, 1 not
covered (inbound malware — Gap C, runtime detection). 4 gaps
closed: VPC endpoint policy decomposition (3 controls), Network
Activity events, anonymous access alerts. The `vpc_endpoint_evasion`
chain models the specific Varonis disclosure scenario. VPC endpoint policy
controls exist for general restrictive-policy checks. The anonymous
access reachability controls (CTL.EXPOSURE.ANON.*) detect
unauthenticated access paths to sensitive resources. Exfiltration
path controls model data-theft via compute with internet egress.

Gaps: VPC endpoint anonymous-access-specific detection (endpoint
policy allows unsigned requests), Network Activity event
configuration (new CloudTrail event type), and compound chain
modeling the specific Varonis evasion scenario.

## What's ready today

### VPC Endpoint and Network Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Endpoint policy not restrictive | CTL.EC2.VPC.ENDPOINT.ACCESS.001 | `network.has_restrictive_policy == false` |
| S3 endpoint policy default | CTL.S3.NETWORK.POLICY.001 | VPC endpoint policy not attached or default full-access |
| Bucket missing VPC condition | CTL.S3.NETWORK.VPC.001 | `has_vpc_condition == false AND has_ip_condition == false` |
| Bucket public-principal no network condition | CTL.S3.NETWORK.001 | `effective_network_scope == public` |
| Missing S3 gateway endpoint | CTL.VPC.ENDPOINT.S3.001 | VPC has no S3 endpoint |

### S3 Access Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Wildcard principal | CTL.S3.ACCESS.002 | `has_wildcard_principal == true` |
| Effectively public policy | CTL.S3.ACCESS.004 | `policy_is_effectively_public == true` |
| Missing scoping condition | CTL.S3.POLICY.SCOPING.001 | Broad policy without scoping condition |
| Block Public Access | CTL.S3.CONTROLS.001 | `public_access_fully_blocked == false` |

### Reachability and Exfiltration Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Anonymous path to sensitive data | CTL.EXPOSURE.ANON.001 | Anonymous path reaches PHI/PII/confidential |
| Anonymous path without auth boundary | CTL.EXPOSURE.ANON.003 | Anonymous path has no authentication boundary |
| Exfil: sensitive data readable + egress | CTL.EXPOSURE.EXFIL.001 | Compute with egress can read sensitive data |
| Exfil: wildcard write + egress | CTL.EXPOSURE.EXFIL.002 | Compute with egress has wildcard write |

### Monitoring Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| S3 policy change monitoring | CTL.CLOUDWATCH.MONITOR.S3POLICY.001 | Missing S3 policy change alerts |
| VPC change monitoring | CTL.CLOUDWATCH.MONITOR.VPC.001 | Missing VPC change alerts |
| CloudTrail enabled | CTL.CLOUDTRAIL.ENABLED.001 | Multi-region trail |
| VPC flow logging | CTL.VPC.FLOWLOG.001 | Missing flow logs |

### Chain Definitions

| Chain | Pattern |
|-------|---------|
| `data_exfiltration_path` | Missing data-read logging + exfil path + no flow logs |
| `detection_blindness` | No CloudTrail + no Config + no GuardDuty + no flow logs |

## VPC Endpoint Policy Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Endpoint allows anonymous | CTL.VPC.ENDPOINT.ANON.001 (`endpoint_policy.denies_anonymous`), CTL.EC2.VPC.ENDPOINT.ACCESS.001 (general) | **Full** |
| 2 | No IAM conditions on endpoint | CTL.VPC.ENDPOINT.IAM.CONDITION.001 (`endpoint_policy.requires_iam_conditions`) | **Full** |
| 3 | Allows external bucket access | CTL.VPC.ENDPOINT.BUCKET.RESTRICT.001 (`endpoint_policy.restricts_target_buckets`) | **Full** |

### Vectors 1-3 detail: Partial coverage

The existing endpoint controls check whether the policy IS
restrictive (boolean) but don't decompose WHAT the policy
restricts. The Varonis attack specifically exploits that anonymous
(unsigned) requests bypass IAM-based conditions. A restrictive
policy that requires authentication (aws:PrincipalArn != "") would
block the attack, but the existing controls don't verify this
specific condition.

**Gap classification: Gap B.** Requires observation properties
for endpoint policy condition decomposition:
- `network.vpc_endpoint_policy.denies_anonymous` (bool)
- `network.vpc_endpoint_policy.restricts_target_buckets` (bool)

## S3 Bucket Policy Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 4 | Bucket allows anonymous | CTL.S3.ACCESS.002 (`has_wildcard_principal`), CTL.S3.ACCESS.004 (`policy_is_effectively_public`), CTL.EXPOSURE.ANON.001-003 (anonymous reachability paths) | **Full** |
| 5 | No VPC endpoint restriction | CTL.S3.NETWORK.VPC.001 (`has_vpc_condition == false AND has_ip_condition == false`), CTL.S3.NETWORK.001 (`effective_network_scope == public`) | **Full** |

## Logging/Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 6 | No Network Activity events | CTL.CLOUDTRAIL.NETWORK.ACTIVITY.001 (`network_activity_events.enabled`) | **Full** |
| 7 | No anonymous access alerts | CTL.CLOUDWATCH.MONITOR.ANON.VPC.001 (`anonymous_vpc_access.exists`) | **Full** |
| 8 | No endpoint policy alerts | CTL.CLOUDWATCH.MONITOR.VPC.001, CTL.CLOUDWATCH.MONITOR.ANON.VPC.001 | **Full** |

### Vector 6 detail: Not covered

CloudTrail Network Activity events are a new event type AWS added
to capture VPC endpoint data-plane activity (including anonymous
requests). No control verifies this event type is enabled.

**Gap classification: Gap B.** Requires observation property
`audit_trail.network_activity_events.enabled` on CloudTrail trail
assets.

### Vector 7 detail: Not covered

No CloudWatch metric filter exists for anonymous S3 requests
through VPC endpoints. This is a novel monitoring pattern specific
to the Varonis disclosure.

**Gap classification: Gap B.** Requires observation property
`monitoring.metric_filters.anonymous_vpc_endpoint_access.exists`.

## Exfiltration Coverage Matrix

| # | Vector | Control(s) / Chains | Coverage |
|---|--------|---------------------|----------|
| 9 | Exfil via endpoint | CTL.EXPOSURE.EXFIL.001 (sensitive data + egress path), CTL.VPC.SG.EGRESS.001 (unrestricted egress), `data_exfiltration_path` chain | **Full** |
| 10 | Malware via endpoint | CTL.VPC.SG.EGRESS.001 (egress control). No inbound-threat-via-endpoint control. | **Partial** |

### Vector 10 detail: Partial coverage

Egress controls exist but no control specifically detects inbound
threats (malware download) via VPC endpoints. This is an edge case
— the endpoint provides connectivity, not the threat itself.

**Gap classification: Gap C.** Detecting inbound malware requires
runtime inspection (GuardDuty Malware Protection), not
configuration assessment.

## Compound Coverage Matrix

| # | Vector | Control(s) / Chains | Coverage |
|---|--------|---------------------|----------|
| 11 | Full evasion chain | `vpc_endpoint_evasion` chain (ENDPOINT.ANON + ENDPOINT.BUCKET.RESTRICT + CLOUDTRAIL.NETWORK.ACTIVITY) | **Full** |
| 12 | End-to-end exfil | `vpc_endpoint_evasion` chain + `data_exfiltration_path` chain | **Full** |

### Vector 11: Highest-value gap

This is the specific Varonis scenario: permissive endpoint policy +
anonymous bucket access + no Network Activity logging = completely
undetected data access. A `vpc_endpoint_evasion` chain composing
endpoint, bucket, and logging controls would directly model this.

**Gap classification: Gap A** (chain gap — component controls
exist or are closable with Gap B properties).

## Mitigation Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 13 | Endpoint least privilege | CTL.EC2.VPC.ENDPOINT.ACCESS.001, CTL.S3.NETWORK.POLICY.001 | **Full** |
| 14 | Bucket policy audit | CTL.S3.ACCESS.002, CTL.S3.ACCESS.004, CTL.S3.NETWORK.VPC.001, CTL.S3.POLICY.SCOPING.001 (comprehensive bucket policy analysis) | **Full** |
| 15 | Policy change alerts | CTL.CLOUDWATCH.MONITOR.S3POLICY.001, CTL.CLOUDWATCH.MONITOR.VPC.001 | **Full** |

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 1-3 | Endpoint anonymous/conditions/buckets | — | **CLOSED** | CTL.VPC.ENDPOINT.ANON/BUCKET.RESTRICT/IAM.CONDITION.001 |
| 6 | Network Activity events | — | **CLOSED** | CTL.CLOUDTRAIL.NETWORK.ACTIVITY.001 |
| 7 | Anonymous VPC endpoint alerts | — | **CLOSED** | CTL.CLOUDWATCH.MONITOR.ANON.VPC.001 |
| 10 | Inbound malware via endpoint | C | Low | Runtime detection, not configuration — deferred |
| 11 | Full evasion chain | — | **CLOSED** | `vpc_endpoint_evasion` chain |

## Observation Schema Assessment

**VPC endpoint assets:** `aws_vpc_endpoint` exists with
`network.has_restrictive_policy` boolean. Policy condition
decomposition (anonymous deny, bucket restriction, IAM conditions)
not yet captured.

**S3 network properties:** Mature — `storage.network.vpc_endpoint_policy.*`,
`storage.access.has_vpc_condition`, `storage.access.effective_network_scope`.
These directly address bucket-side mitigations.

**CloudTrail:** No `network_activity_events` property exists.
This is a new event type.

## Recommendations

**Ship now:** Enable all 20+ controls and the `vpc_endpoint_evasion`
chain. 14/15 vectors fully covered including the specific Varonis
disclosure scenario.

**Deferred:**
- Vector 10: Inbound malware detection. Runtime concern, not
  configuration assessment (Gap C).

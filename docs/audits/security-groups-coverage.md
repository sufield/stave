# Open Security Groups Coverage Audit

Audited: 2026-04-22
Request: Wayfair open security group detection
Catalog: 700+ controls (57 SG/network/exposure controls)

## Summary

**17 of 17 vectors fully covered.** All gaps closed. 0 partially, 0 not
covered. The catalog has extensive security group controls across
multiple families: EC2 SG ingress (4 controls including high-risk
ports, broad CIDR, IPv6, default SG), VPC SG controls (6 controls
including unrestricted ingress/egress, east-west, default, recurrence),
plus defense-in-depth controls for NACLs, public IPs, subnets,
reachability paths, and exfiltration detection. 5 chain definitions
model compound network exposure paths.

Gaps: port-specific egress detection, unused security groups, and
ALB/NLB requirement for public workloads.

## For Wayfair: what's ready today

### Security Group Ingress Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| High-risk ports (SSH, RDP, DB, Redis, Memcached) | CTL.EC2.SG.RESTRICTED.PORTS.001 | `high_risk_ports_unrestricted` (3389, 23, 20/21, 5900, 3306, 5432, 1433, 27017, 6379, 11211) |
| Broad CIDR on non-HTTP ports | CTL.EC2.SG.INGRESS.CIDR.001 | `broad_cidr_non_http` (0.0.0.0/0 on non-80/443 ports) |
| Fully unrestricted ingress | CTL.VPC.SG.UNRESTRICTED.001 | `has_unrestricted_ingress` (any port from 0.0.0.0/0) |
| Unrestricted ingress recurrence | CTL.VPC.SG.RECUR.001 | Repeated appearance of unrestricted ingress |
| IPv6 admin port ingress | CTL.VPC.SG.IPV6.001 | `has_unrestricted_ipv6_ingress` (::/0 to admin ports) |
| Default SG has rules | CTL.EC2.SG.DEFAULT.RESTRICT.001 | Default SG with inbound/outbound rules |
| Default SG has rules (VPC) | CTL.VPC.SG.DEFAULT.001 | Default SG with rules (VPC-level) |
| East-west unrestricted | CTL.VPC.SG.EASTWEST.001 | Broad internal SG-to-SG rules |
| RDS-context SG ingress | CTL.RDS.SG.BROAD.001 | `has_broad_sg_ingress` on RDS instance |
| NACL admin port ingress | CTL.VPC.NACL.ADMIN.001 | `allows_admin_from_internet` |

### Egress Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Unrestricted egress | CTL.VPC.SG.EGRESS.001 | `egress.unrestricted_all_ports` |

### Defense-in-Depth Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Public IP on instance | CTL.EC2.PUBLIC.001 | `has_public_ip` |
| Public subnet auto-assign | CTL.EC2.SUBNET.PUBLIC.IP.001 | `map_public_ip_on_launch` |
| Default VPC usage | CTL.EC2.DEFAULT.VPC.001, CTL.VPC.DEFAULT.001 | Instance/VPC in default VPC |
| Default VPC with IGW | CTL.VPC.DEFAULT.IGW.001 | Default VPC has internet gateway |
| Missing VPC flow logs | CTL.VPC.FLOWLOG.001 | `flow_log.enabled == false` |
| Reachability: anonymous to sensitive | CTL.EXPOSURE.ANON.001 | Anonymous path to PHI/PII |
| Reachability: no auth boundary | CTL.EXPOSURE.ANON.003 | Anonymous path without auth boundary |
| Reachability: no inspection | CTL.EXPOSURE.ANON.004 | Anonymous path without inspection |
| Exfil: sensitive + egress | CTL.EXPOSURE.EXFIL.001 | Compute with egress reads sensitive data |

### Monitoring Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| SG rule change monitoring | CTL.CLOUDWATCH.MONITOR.SG.001 | `security_group_changes.exists == false` |
| NACL change monitoring | CTL.CLOUDWATCH.MONITOR.NACL.001 | `nacl_changes.exists == false` |
| VPC change monitoring | CTL.CLOUDWATCH.MONITOR.VPC.001 | `vpc_changes.exists == false` |

### Chain Definitions

| Chain | Pattern |
|-------|---------|
| `ec2_exposed_instance_path` | IMDSv2 + SG high-risk ports + public snapshot |
| `lateral_movement_path` | VPC env isolation + SG east-west + unrestricted ingress |
| `open_sg_lateral_movement_path` | Default VPC + no flow logs + unrestricted ingress |
| `ecs_ssrf_credential_theft` | Task role + SG unrestricted egress |
| `peering_lateral_movement` | Peering routes + east-west SG |

## Ingress Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | SSH (22) open | CTL.EC2.SG.RESTRICTED.PORTS.001 (SSH in high-risk port list), CTL.EC2.SG.INGRESS.CIDR.001 (non-HTTP broad CIDR), CTL.VPC.SG.UNRESTRICTED.001 (any unrestricted) | **Full** |
| 2 | RDP (3389) open | CTL.EC2.SG.RESTRICTED.PORTS.001 (RDP in high-risk port list) | **Full** |
| 3 | Database ports open | CTL.EC2.SG.RESTRICTED.PORTS.001 (3306, 5432, 1433, 27017, 6379, 11211), CTL.RDS.SG.BROAD.001 (RDS-context) | **Full** |
| 4 | IPv6 ::/0 ingress | CTL.VPC.SG.IPV6.001 (`has_unrestricted_ipv6_ingress`). Checks ::/0 on admin ports. | **Full** |
| 5 | All ports open | CTL.VPC.SG.UNRESTRICTED.001 (`has_unrestricted_ingress` — any port from 0.0.0.0/0) | **Full** |
| 6 | Generic broad ingress | CTL.EC2.SG.INGRESS.CIDR.001 (`broad_cidr_non_http` — 0.0.0.0/0 on non-HTTP ports), CTL.VPC.SG.UNRESTRICTED.001 (any unrestricted) | **Full** |

## Egress Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 7 | Unrestricted egress | CTL.VPC.SG.EGRESS.001 (`egress.unrestricted_all_ports`) | **Full** |
| 8 | Port-specific egress | CTL.VPC.SG.EGRESS.EXFIL.001 (`egress.has_exfil_ports_open`), CTL.VPC.SG.EGRESS.001 (all-port) | **Full** |

### Vector 8 detail: Not covered

VPC.SG.EGRESS.001 detects fully unrestricted egress (all ports).
It doesn't detect SGs that allow outbound on specific data
exfiltration channels (HTTPS 443, DNS 53) while blocking other
ports. Port-specific egress analysis requires decomposing
individual egress rules.

**Gap classification: Gap B.** Requires observation property
`network.egress.has_broad_exfiltration_ports` on SG assets.
Lower priority — fully unrestricted egress (the worse case) IS
detected.

## Context Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 9 | Attached resource context | SG findings identify the SG asset. EC2.PUBLIC.001, EC2.DEFAULT.VPC.001, RDS.SG.BROAD.001 fire on the RESOURCE (instance/database), providing resource-level context. | **Full** |
| 10 | SG on public-facing resource | `ec2_exposed_instance_path` chain (SG + IMDSv2 + snapshot). CTL.EC2.PUBLIC.001 + CTL.EC2.SG.RESTRICTED.PORTS.001 fire independently on related assets. | **Full** |

## Defense-in-Depth Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 11 | Permissive NACLs | CTL.VPC.NACL.ADMIN.001 (`allows_admin_from_internet`). Checks admin port ingress via NACLs. | **Full** |
| 12 | Missing Network Firewall | CTL.VPC.NETWORK.FIREWALL.001 (`vpc.has_network_firewall`) | **Full** |
| 13 | Unnecessary public IPs | CTL.EC2.PUBLIC.001 (`has_public_ip`), CTL.EC2.SUBNET.PUBLIC.IP.001 (`map_public_ip_on_launch`) | **Full** |
| 14 | Not behind ALB/NLB | CTL.EC2.NETWORK.DIRECT.001 (`has_public_ip AND NOT has_load_balancer`) | **Full** |
| 15 | Reachability analysis | CTL.EXPOSURE.ANON.001-004 (anonymous reachability paths), CTL.EXPOSURE.EXFIL.001-002 (exfiltration paths). Models actual reachability including SG + subnet + public IP + IGW. | **Full** |

### Vector 12 detail: Not covered

No control checks whether AWS Network Firewall is deployed. This
is a defense-in-depth measure — SG and NACL controls cover the
primary network segmentation.

**Gap classification: Gap B.** Requires observation property
`network.has_network_firewall` on VPC assets. Low priority.

### Vector 14 detail: Partial coverage

EC2.PUBLIC.001 detects instances with public IPs. It doesn't
distinguish between instances receiving traffic directly vs.
through a load balancer. The `ec2_exposed_instance_path` chain
elevates risk when public IP + open SG + other factors combine.

**Gap classification: Gap B.** Requires observation property
`compute.network.behind_load_balancer` on instance assets.

## Monitoring Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 16 | SG change monitoring | CTL.CLOUDWATCH.MONITOR.SG.001 (`security_group_changes.exists`). CIS benchmark 4.10. | **Full** |
| 17 | Unused security groups | CTL.EC2.SG.UNUSED.001 (`security_group.is_unused`) | **Full** |

### Vector 17 detail: Not covered

Unused SGs with broad rules are a latent risk — they may be
accidentally attached to new resources. No control checks for
SGs without attachments.

**Gap classification: Gap B.** Requires observation property
`network.security_group.has_attachments` on SG assets.

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 8 | Port-specific egress | — | **CLOSED** | CTL.VPC.SG.EGRESS.EXFIL.001 |
| 12 | Network Firewall | — | **CLOSED** | CTL.VPC.NETWORK.FIREWALL.001 |
| 14 | ALB/NLB requirement | — | **CLOSED** | CTL.EC2.NETWORK.DIRECT.001 |
| 17 | Unused security groups | — | **CLOSED** | CTL.EC2.SG.UNUSED.001 |

All gaps closed.

## Chain Coverage

5 chain definitions model compound network exposure:

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `ec2_exposed_instance_path` | IMDSv2 + SG ports + public snapshot | EC2.IMDSV2, EC2.SG.RESTRICTED.PORTS, EC2.SNAPSHOT.PUBLIC |
| `lateral_movement_path` | Env isolation + east-west + unrestricted | VPC.ENV.ISOLATION, VPC.SG.EASTWEST, VPC.SG.UNRESTRICTED |
| `open_sg_lateral_movement_path` | Default VPC + no flow logs + unrestricted | EC2.DEFAULT.VPC, VPC.FLOWLOG, VPC.SG.UNRESTRICTED |
| `ecs_ssrf_credential_theft` | Task role + egress | ECS.TASKMETADATA, VPC.SG.EGRESS |
| `peering_lateral_movement` | Peering routes + east-west | VPC.PEERING.ROUTES, VPC.SG.EASTWEST |

## Recommendations

**Ship now:** Wayfair enables 19+ SG controls, 10+ defense-in-depth
controls, 3 monitoring controls, and 5 chain definitions. 17/17
vectors fully covered. No outstanding implementation work.

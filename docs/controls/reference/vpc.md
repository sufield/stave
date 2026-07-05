# Control Reference — VPC

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.VPC.CLIENTVPN.AUTH.001

**Client VPN Allows All Traffic Without Authorization Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Client VPN endpoint has no authorization rules or has a rule that allows all traffic to 0.0.0.0/0 across every associated subnet. Any VPN user who connects can reach every resource in every subnet the endpoint is attached to. Authorization rules should restrict access to specific destination CIDRs based on user-group membership so that a single compromised credential does not grant full VPC access.

**Remediation:** Define authorization rules that restrict each user group to the specific destination CIDRs that group requires. Remove any 0.0.0.0/0 allow-all rule. Map user groups from the authentication provider (SAML, Active Directory, mutual certificate CN) to destination CIDRs and enforce least privilege per group.

---

### CTL.VPC.CLIENTVPN.LOGGING.001

**Client VPN Connection Logging Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Client VPN connection logging is not enabled. The endpoint does not record who connected, when they connected, from what source IP, for how long, or which authorization rules their traffic matched. After a credential compromise, there is no way to identify which VPN sessions were the attacker's — every connection is indistinguishable from legitimate use.

**Remediation:** Enable connection logging on the Client VPN endpoint. Route records to a CloudWatch Logs group in a logging-dedicated account. Retain records per incident-response and compliance requirements. Alert on unusual source-IP patterns, sessions outside business hours, and repeated authentication failures.

---

### CTL.VPC.CLIENTVPN.SPLITTUNNEL.001

**Client VPN Split Tunneling Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: AC-17; hipaa: 164.312(e)(1); nist_800_53_r5: AC-17; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

Client VPN endpoint has split tunneling enabled. Only VPC-destined traffic routes through the VPN; all other traffic leaves the client device directly to the internet. The client is simultaneously connected to the trusted VPC and the untrusted internet. An attacker who compromises the device via the internet path (malicious website, phishing, drive-by download) can pivot directly into the VPC through the VPN — the laptop becomes the corporate network perimeter. Split tunneling is a legitimate choice for bandwidth-sensitive use cases; triage should weigh that tradeoff rather than prescribe full-tunnel unconditionally.

**Remediation:** Disable split tunneling so all client traffic routes through the VPN and passes through corporate security controls (firewall, proxy, DLP). If split tunneling is a documented business need (bandwidth-sensitive use cases, specific SaaS allowlist), keep it but compensate with strict endpoint hardening: EDR, host firewall, mandatory OS patching, and application allowlisting on the client device itself.

---

### CTL.VPC.DEFAULT.001

**Default VPC Must Not Be Used**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Workloads must not run in the default VPC. The default VPC is created automatically in every region with permissive settings: a public subnet in each AZ, an internet gateway, and a default security group that allows all internal traffic. These defaults create implicit public exposure that custom VPCs avoid. Production and sensitive workloads must use purpose-built VPCs with explicit network design.

**Remediation:** Create a custom VPC with private subnets, explicit route tables, and restrictive security groups. Migrate workloads from the default VPC. Consider deleting the default VPC in production accounts if no workloads require it.

---

### CTL.VPC.DEFAULT.IGW.001

**Default VPC Must Not Have Internet Gateway Route**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.7; nist_800_53_r5: SC-7;

The default VPC must not have an internet gateway route in its route tables. AWS creates a default VPC in every region with a route table that sends all internet-bound traffic through an attached internet gateway. Resources launched into the default VPC without explicit network configuration receive a public IP and are directly reachable from the internet. The default VPC is frequently used for ad-hoc testing and forgotten resources — any instance, Lambda VPC attachment, or RDS instance placed in the default VPC inherits internet exposure by default. Removing the internet gateway route from the default VPC eliminates this accidental exposure path without affecting production workloads which should be in purpose-built VPCs.

**Remediation:** Remove the internet gateway route from the default VPC route table. Detach and delete the internet gateway from the default VPC if no resources require it. Alternatively, delete the default VPC entirely if it is not in use. Verify no active resources depend on the default VPC internet connectivity before removing the route.

---

### CTL.VPC.DEFAULT.RESOURCES.001

**Resources Deployed in Default VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Active resources (EC2 instances, RDS instances, VPC-configured Lambda functions, ECS tasks) exist in the default VPC. The default VPC ships with unsafe defaults: public subnets in every AZ with `MapPublicIpOnLaunch` enabled, a default security group that permits all intra-VPC traffic, and an Internet Gateway. Production workloads inherit all of those defaults. Strengthens `CTL.VPC.DEFAULT.001` (which detects the default VPC's existence) by focusing on the actionable problem — resources deployed in it.

**Remediation:** Migrate resources out of the default VPC into a purpose-built VPC with non-default subnets, route tables, and security groups. If migration is not feasible short-term, harden the default VPC in place: remove auto-assign public IP on its subnets, restrict the default security group to deny-all, and detach the default IGW if the resources do not need internet access. Do not deploy new workloads into the default VPC.

---

### CTL.VPC.DHCP.NTP.EXTERNAL.001

**VPC DHCP Option Sets Must Use Amazon Time Sync or Authenticated NTP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AU-8, SC-45; soc2: CC7.2;

A VPC's DHCP option set specifies external public NTP servers (a pool such as pool.ntp.org or public IPs like the NIST servers 129.6.15.28/29) in its `ntp-servers` option. The DHCP option set is the VPC-wide default, so EVERY instance in the VPC that takes its NTP servers from DHCP inherits an unauthenticated, network-spoofable time source — one setting that skews the clock of the whole VPC. Time is effectively part of the cloud control plane; an adversary who can influence it undermines certificate validation, token expiry, and log-timestamp ordering fleet-wide.
The collector sets `network.vpc.dhcp_ntp_external` true when the option set's `ntp-servers` lists any address that is neither the Amazon Time Sync link-local endpoint (169.254.169.123) nor a private (RFC 1918) address. Unset `ntp-servers` is safe — instances fall back to the Amazon Time Sync link-local default. A private internal NTP server passes here; verifying that server's OWN upstream is authenticated is out of snapshot scope (INFO).
Inspired by NCC Group "Time as an Attack Surface" white paper by Andy Davis.

**Remediation:** Remove external servers from the DHCP option set's `ntp-servers` (leave it unset to use the Amazon Time Sync link-local default), or set it to 169.254.169.123. If you must run an internal NTP server, confirm that server itself syncs from Amazon Time Sync or an authenticated upstream.

---

### CTL.VPC.DNS.HOSTNAMES.001

**VPC Must Have DNS Hostnames Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-22; soc2: CC6.6;

VPC does not have DNS hostnames (EnableDnsHostnames) enabled. Without DNS hostnames, EC2 instances do not receive public DNS hostnames, preventing external resolution to their public IPs and breaking patterns that depend on hostname-based identity (ACM certificate validation, some load balancer health checks). Required for VPC endpoints to generate private DNS entries.

**Remediation:** Enable DNS hostnames on the VPC.

---

### CTL.VPC.DNS.RESOLUTION.001

**VPC Must Have DNS Resolution Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-22; soc2: CC6.6;

VPC does not have DNS resolution (EnableDnsSupport) enabled. Without DNS resolution, instances cannot resolve public DNS hostnames to private IP addresses within the VPC, breaking VPC endpoint connectivity and service discovery. Required for VPC endpoints, PrivateLink, and Route 53 Resolver integration.

**Remediation:** Enable DNS resolution on the VPC.

---

### CTL.VPC.DNSFIREWALL.ENABLED.001

**VPC Does Not Have DNS Firewall**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-20; nist_800_53_r5: SC-20; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

VPC has no Route53 Resolver DNS Firewall rule group associated. DNS queries from instances in the VPC are resolved without filtering. Instances can resolve domains used for command-and- control (C2), malware download, cryptomining pool coordination, DNS-tunneled exfiltration, and phishing infrastructure. DNS is an often-overlooked egress channel — even when TCP/UDP egress is restricted by security groups, DNS resolution proceeds through the VPC resolver and can leak data in query names or confirm target reachability to attacker infrastructure.

**Remediation:** Associate a DNS Firewall rule group with the VPC. Start with the two AWS managed lists: `AWSManagedDomainsMalwareDomainList` and `AWSManagedDomainsBotnetCommandAndControlDomainList`. Add custom rules for organization-specific blocklists (known phishing lures, ex-vendor domains). Set the rule action to BLOCK for malicious categories and optionally ALERT for newer or lower-confidence feeds during tuning.

---

### CTL.VPC.DNSFIREWALL.MANAGEDLISTS.001

**DNS Firewall Not Using AWS Managed Domain Lists**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; nist_800_53_r5: SI-3; pci_dss_v4.0: 5.1.1; soc2: CC6.6;

DNS Firewall is associated with the VPC but the rule group does not include AWS managed domain lists (`AWSManagedDomainsMalwareDomainList`, `AWSManagedDomainsBotnetCommandAndControlDomainList`, and the aggregate list). The managed lists are maintained by AWS threat intelligence teams and updated as new malicious domains are observed. A DNS Firewall with only custom rules misses industry-wide threat intelligence. Custom rules are appropriate for organization-specific blocklists (ex-vendor domains, phishing lures targeting the company) and belong alongside the managed feeds, not instead of them.

**Remediation:** Add the AWS managed lists to the DNS Firewall rule group: `AWSManagedDomainsMalwareDomainList`, `AWSManagedDomainsBotnetCommandAndControlDomainList`, and `AWSManagedDomainsAggregateThreatList`. Set priorities so the managed lists evaluate before custom rules (or after, if organization-specific blocks should take precedence). Managed lists update automatically; no operational overhead.

---

### CTL.VPC.DX.BGP.001

**Direct Connect BGP Must Use Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.6;

Direct Connect virtual interfaces must configure BGP MD5 authentication. Without BGP authentication, an attacker on the same physical link or co-location facility can inject BGP route advertisements, redirecting traffic through attacker-controlled paths. BGP MD5 authentication prevents unauthorized route injection.

**Remediation:** Configure BGP authentication key on the virtual interface: aws directconnect create-private-virtual-interface --connection-id <id> --new-private-virtual-interface authKey=<md5-key>,...

---

### CTL.VPC.DX.ENCRYPTION.001

**Direct Connect Without Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Direct Connect connection carries unencrypted traffic. Neither a site-to-site VPN overlay nor MACsec is configured. Direct Connect is a dedicated physical link — not shared with other customers — but the traffic on it is plaintext by default. Anyone with physical access to the fiber path (datacenter staff, transit providers, co-location personnel) can tap the connection and read traffic. Either a VPN over the Direct Connect or MACsec provides confidentiality; the control passes if either is configured.

**Remediation:** Add encryption to the Direct Connect path. Either (a) configure a site-to-site VPN over the Direct Connect connection and route all traffic through the VPN, or (b) enable MACsec on the Direct Connect ports (supported on 10 Gbps and 100 Gbps dedicated connections). VPN overlay is more widely supported; MACsec offers lower latency but requires compatible hardware on both ends.

---

### CTL.VPC.DX.GATEWAY.001

**Direct Connect Gateway Must Have Virtual Interface Associations**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

A Direct Connect gateway without virtual interface (VIF) associations is an unused resource consuming a dedicated physical connection. An unassociated gateway may indicate incomplete setup (traffic still routes over the internet) or a decommissioned circuit that was not cleaned up.

**Remediation:** Associate a virtual interface with the gateway, or delete the unused gateway. Use aws directconnect create-private-virtual-interface to create a VIF, or delete-direct-connect-gateway to remove it.

---

### CTL.VPC.DX.RESILIENCY.001

**Direct Connect Must Have Redundant Connections**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-8; scs_c02: 9.1; soc2: A1.2;

AWS Direct Connect should have at least two connections for resiliency. A single DX connection is a single point of failure — if the connection, port, or the DX location itself fails, all hybrid connectivity is lost. AWS recommends at minimum two connections at different DX locations for production workloads. Without redundancy, a physical failure at one location takes down the entire hybrid network path.

**Remediation:** Provision a second Direct Connect connection at a different DX location. Configure BGP failover between the two connections. Consider using DX SiteLink for multi-site resiliency.

---

### CTL.VPC.EIP.EXCESSIVE.001

**Instance Has Multiple Elastic IPs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

EC2 instance has more than one Elastic IP associated. Multiple public addresses on a single instance indicate over-exposure — the instance is reachable via multiple distinct network paths, broadening the attack surface and complicating firewall rules, monitoring, and incident response. Legitimate use cases (multi- tenant ingress, specific licensing requirements) exist but are unusual and should be explicitly justified.

**Remediation:** Review the use case for each attached EIP. Retain only the minimum set required; release the extras and reassign dependents. If multiple EIPs are genuinely required, document the reason on the instance tag and ensure each address is covered by the same security group rules and monitoring as the primary address.

---

### CTL.VPC.EIP.ORPHANED.001

**Elastic IP Not Associated with Any Resource**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; soc2: CC7.1;

Elastic IP is allocated but not associated with an instance, NAT gateway, or network interface. Orphaned EIPs are a lifecycle gap — the resource the EIP was attached to was deleted but the EIP was not released. The security relevance is the lifecycle signal: if EIPs are not cleaned up, related resources (security groups, route table entries, IAM policies referencing IPs) are likely also accumulating without review. Orphaned EIPs also carry an ongoing charge and count against the per-region limit.

**Remediation:** Release the orphaned EIP with `aws ec2 release-address`. Add an allocation-age check to your housekeeping automation so EIPs that sit unassociated for longer than a defined threshold (for example seven days) are reported and released. Review neighboring resources (security groups, route tables) for matching staleness.

---

### CTL.VPC.ENDPOINT.ANON.001

**VPC Endpoint Policy Must Deny Anonymous Requests**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.6;

VPC endpoint policies must explicitly deny anonymous (unsigned) requests. Without this, unauthenticated S3 requests can transit the endpoint without identity information, evading CloudTrail logging and IAM policy evaluation.

**Remediation:** Add a Deny statement to the endpoint policy for requests where aws:PrincipalArn does not exist (anonymous/unsigned requests).

---

### CTL.VPC.ENDPOINT.BUCKET.RESTRICT.001

**VPC Endpoint Policy Must Restrict Target S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

VPC endpoint policies for S3 must restrict which buckets can be accessed. Without Resource constraints, any S3 bucket globally — including attacker-controlled buckets — is reachable through the organization's endpoint.

**Remediation:** Add a Resource constraint to the endpoint policy listing only the organization's buckets. Deny all other bucket ARNs.

---

### CTL.VPC.ENDPOINT.CROSSACCOUNT.001

**VPC Endpoint Policy Must Not Allow Cross-Account Resource Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.1;

VPC endpoint policies must not allow access to resources in external accounts. An endpoint policy with Resource ARNs containing account IDs different from the VPC's own account creates an explicit cross-account data path through the organization's network. A compromised workload or indirect prompt injection can use this path to exfiltrate data to the external account's resources without triggering IAM policy denials.

**Remediation:** Remove cross-account resource ARNs from the endpoint policy. Restrict the Resource field to ARNs within the VPC's own account, or add an aws:ResourceOrgID condition to limit access to organizational resources.

---

### CTL.VPC.ENDPOINT.DNS.001

**Interface VPC Endpoint Private DNS Not Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Interface VPC endpoint does not have Private DNS enabled. Without Private DNS, the standard service DNS name (for example `kms.us-east-1.amazonaws.com`) resolves to the service's public IP — not to the VPC endpoint. Applications using the standard SDK configuration bypass the endpoint entirely: traffic routes through the NAT gateway to the public endpoint. The VPC endpoint exists but is unused because DNS does not point at it. Private DNS makes the standard service name resolve to the endpoint's private IP, so every SDK call routes through the endpoint without code changes. Low severity because the finding rarely causes outages — but the behavior surprises most teams because the endpoint appears to be in use when it is not.

**Remediation:** Enable Private DNS on the interface endpoint. This changes the VPC's DNS resolution so the standard service DNS name resolves to the endpoint's private IP, routing all SDK traffic through the endpoint without code changes. If Private DNS cannot be enabled (conflicts with an overlapping resolver configuration), configure application SDKs to use the endpoint's VPCE-specific DNS name explicitly — but the simpler fix is Private DNS.

---

### CTL.VPC.ENDPOINT.GHOST.001

**VPC Endpoint Policy Must Not Reference Deleted Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

VPC endpoint policies must not grant access to resources by ARN when those resources no longer exist. For S3 bucket ARNs (globally reclaimable), traffic routed through the endpoint reaches whoever claims the bucket name. For account-scoped resources, an attacker with limited access can recreate the resource.

**Remediation:** Remove the ghost resource ARN from the endpoint policy.

---

### CTL.VPC.ENDPOINT.IAM.CONDITION.001

**VPC Endpoint Policy Must Require IAM Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

VPC endpoint policies must include IAM conditions (aws:PrincipalArn, aws:PrincipalOrgID) to verify the identity of requesters. Without these, any principal in the VPC can use the endpoint without identity verification at the policy layer.

**Remediation:** Add aws:PrincipalArn or aws:PrincipalOrgID conditions to the endpoint policy to restrict which principals can use it.

---

### CTL.VPC.ENDPOINT.MISSING.CRITICAL.001

**VPC Missing Interface Endpoints for Critical AWS Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

VPC with private subnets does not have interface endpoints for one or more critical security services: KMS, Secrets Manager, STS, SSM, CloudWatch Logs, ECR. Traffic to these services either fails (no NAT) or exits through the NAT gateway to the public endpoint over the internet. Each of these services carries sensitive data or credentials — KMS operations on encryption keys, Secrets Manager secret retrieval, STS AssumeRole calls, SSM session and parameter data, CloudWatch Logs ingestion, ECR image pulls. Keeping this traffic on AWS's internal network via interface endpoints eliminates the public-internet leg and enables endpoint-policy scoping. The critical-services list is configurable via the `critical_services_missing` observation field — the finding enumerates exactly which services lack coverage so remediation is specific.

**Remediation:** Create interface VPC endpoints for the missing services (KMS, Secrets Manager, STS, SSM, CloudWatch Logs, ECR). Enable Private DNS on each so existing SDK calls route automatically through the endpoint. Scope each endpoint's security group to the subnets or SGs that actually use the service, not the whole VPC. Consider an endpoint policy that restricts which principals (by OrgID or AccountID) can use the endpoint.

---

### CTL.VPC.ENDPOINT.ORGRESTRICTION.001

**VPC Endpoint Policy Must Restrict Destination to Organizational Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

VPC endpoint policies for data services (S3, DynamoDB, Secrets Manager, Bedrock, SageMaker) must restrict access to organizational resources using aws:ResourceOrgID, aws:ResourceAccount, or specific resource ARNs. Without destination restriction, a compromised workload can reach any resource in the service globally — including attacker-controlled resources in external accounts — through the organization's own endpoint. This is the network-level enforcement layer that catches what IAM policy gaps miss.

**Remediation:** Add an aws:ResourceOrgID condition to the endpoint policy to restrict access to resources owned by your organization, or restrict the Resource field to specific resource ARNs.

---

### CTL.VPC.ENDPOINT.S3.001

**VPCs Must Have an S3 Gateway Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 4.13; nist_800_53_r5: SC-7;

VPCs must have an S3 VPC gateway endpoint to route S3 traffic privately through the AWS network. Without it, S3 access traverses the public internet, enabling monitoring and interception of data transfers.

**Remediation:** aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --service-name com.amazonaws.<region>.s3 --route-table-ids <route-table-id>

---

### CTL.VPC.ENDPOINT.SG.BROAD.001

**Interface Endpoint Security Group Matches Full VPC CIDR**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Interface VPC endpoint's security group permits inbound traffic from the entire VPC CIDR rather than from specific subnets or other security groups. Every resource in the VPC — including resources that have no business using the service — can reach the endpoint. A compromised instance can call KMS, fetch secrets, assume roles, or pull ECR images via the endpoint without any additional firewall exemption. The endpoint security group should be scoped to the subnets or SGs whose workloads actually use the service.

**Remediation:** Tighten the endpoint security group so inbound is permitted only from the security groups (or subnet CIDRs) of workloads that legitimately need the service. For example, only application-tier SGs should reach the KMS or Secrets Manager endpoint; logging-tier SGs should reach the CloudWatch Logs endpoint. Broad inbound here negates the principle of least privilege the endpoint was created to support.

---

### CTL.VPC.ENV.ISOLATION.001

**Production VPC Must Be Isolated from Non-Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.8.22; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Production VPCs must not share network boundaries with non-production environments. When production and dev/staging workloads share a VPC, a misconfiguration or compromise in a lower environment can reach production resources through security group rules, VPC peering, or shared subnets. Environment isolation requires separate VPCs with explicit, auditable cross-VPC connections.

**Remediation:** Create separate VPCs for each environment (prod, staging, dev). Tag VPCs with an environment classification tag. Use VPC peering or Transit Gateway with explicit route tables for any required cross-environment communication. Ensure security groups do not reference resources in other environments.

---

### CTL.VPC.FLOWLOG.001

**VPC Flow Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.9; cis_aws_v3.0: 3.7; fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 1.2.1; soc2: CC7.1;

VPC flow logs capture information about IP traffic going to and from network interfaces. Without flow logs, network-level access patterns cannot be audited and unauthorized traffic goes undetected.

**Remediation:** Enable VPC flow logs to CloudWatch Logs or S3. Run: aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-xxx --traffic-type ALL --log-destination-type cloud-watch-logs

---

### CTL.VPC.FLOWLOG.BIDIRECTIONAL.001

**Flow Log Captures Only One Traffic Direction**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Flow log's `TrafficType` is set to ACCEPT or REJECT rather than ALL. Capturing only ACCEPT hides blocked traffic — there is no record of what the security groups and NACLs stopped, so reconnaissance and blocked-attack patterns are invisible. Capturing only REJECT hides successful connections — no record of what traffic got through, so lateral movement and data exfiltration via permitted flows cannot be reconstructed. ALL records both so each question (what was blocked, what got through) has a log entry.

**Remediation:** Change the flow log's `TrafficType` to ALL. Storage overhead of ALL vs ACCEPT or REJECT is significant only at very high packet rates; for most workloads the additional volume is worth the complete visibility. If cost is a concern at scale, compress retention periods or sample at the destination rather than narrowing capture at the source.

---

### CTL.VPC.FLOWLOG.DESTINATION.SECURE.001

**Flow Log Destination Not Adequately Secured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-9; hipaa: 164.312(b); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.3.1; soc2: CC7.2;

The S3 bucket or CloudWatch log group receiving flow log records has at least one security weakness: public access allowed, encryption not enabled, deletion allowed without MFA, or retention below 365 days. Flow logs contain network metadata (source, destination, ports, protocols, byte and packet counts) that is valuable both for defenders (forensics, anomaly detection) and for attackers (network mapping, service discovery). If the destination is publicly accessible, the attacker reads the network topology. If the destination allows deletion, the attacker removes evidence of their network activity. If retention is too short, historical data needed for investigation expires before it can be consulted.

**Remediation:** For an S3 destination: enable Block Public Access at the bucket level, enable default encryption with KMS, enable object lock or MFA-delete for deletion protection, and confirm the bucket policy denies principals outside the organization. For a CloudWatch Logs destination: set retention to at least 365 days, apply a resource policy that prevents deletion by non-privileged principals, and enable KMS encryption on the log group.

---

### CTL.VPC.FLOWLOG.ENCRYPT.001

**VPC Flow Logs Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

VPC flow logs contain network metadata (source/destination IPs, ports, protocols). When stored in S3, flow logs must be encrypted with a customer-managed KMS key to protect network topology information.

**Remediation:** Configure flow log destination with SSE-KMS encryption. For S3 destinations, enable default bucket encryption with a CMK.

---

### CTL.VPC.FLOWLOG.FORMAT.001

**Flow Log Missing Critical Fields**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-3; hipaa: 164.312(b); nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.2; soc2: CC7.2;

Flow log uses the default log format, which omits several fields useful for security analysis: vpc-id, subnet-id, tcp-flags, pkt-srcaddr, pkt-dstaddr, flow-direction. A custom log format that includes these fields substantially improves forensics capability — pkt-srcaddr/pkt-dstaddr show the pre-NAT addresses that map flows back to private-subnet origins, and tcp-flags distinguish established connections from SYN scans. The default format was designed for network-operations use cases and leaves security investigators reconstructing the missing context from other sources.

**Remediation:** Change the flow log's format to a custom format that includes vpc-id, subnet-id, tcp-flags, pkt-srcaddr, pkt-dstaddr, and flow-direction (in addition to the default fields). AWS provides a recommended security-oriented format in the documentation; copy it and extend with any workload-specific fields. New logs are delivered in the new format once the change is saved.

---

### CTL.VPC.FLOWLOG.STATUS.001

**Flow Log Configured but Not Active**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Flow log record exists but its status is not ACTIVE (or the deliver-status indicates failure). The configuration is present, the console shows "Flow logs: enabled", dashboards report the log as configured — but no records are actually being delivered. Common causes: the IAM role used for delivery lost permissions (modified or deleted), the destination S3 bucket was deleted or had its policy changed, or the CloudWatch log group was deleted. This is the "everything appears to work" pattern for network visibility: every outward indicator says logging is on, and the observability pipeline has actually stopped.

**Remediation:** Inspect the flow log's deliver-status and error messages. Typical fixes: recreate or repair the IAM role the log uses for delivery, restore the destination S3 bucket or CloudWatch log group, or update the bucket policy / retention configuration that is blocking writes. After the fix, confirm the status returns to ACTIVE and that records start arriving in the destination.

---

### CTL.VPC.FLOWLOG.SUBNET.001

**Sensitive Subnet Does Not Have Flow Logs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Subnet flagged as containing sensitive resources (databases, management instances, tagged as critical) has no subnet-level flow logs AND the parent VPC does not have VPC-level flow logs enabled either. At that point, the subnet has no flow-log coverage at any scope. VPC-level logs satisfy the coverage requirement for non-sensitive subnets; sensitive subnets benefit from the extra granularity of subnet-level logs but the control fires only when neither layer is active, to avoid noise on well-covered deployments.

**Remediation:** Enable flow logs at the subnet level for this subnet and route them to the same destination used by the rest of the account (CloudWatch Logs or S3 in a logging-dedicated account). Alternatively, enable VPC-level flow logs if VPC-wide coverage is preferred. Sensitive subnets (databases, management) are usually worth the extra granularity of subnet-level logs on top of VPC-level.

---

### CTL.VPC.IGW.UNNECESSARY.001

**Internet Gateway Attached to VPC Without Internet Requirement**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

VPC has an Internet Gateway attached but no resources have public IP addresses and no subnets have routes pointing to the IGW. The IGW provides internet connectivity that nothing uses — residual from initial setup, or attached for a purpose that no longer exists. An unattached-but-present IGW is a latent attack surface: one route table change (adding 0.0.0.0/0 → IGW to a subnet) or one public IP assignment converts any instance in the VPC from private to internet-facing. For VPCs intended to have no internet connectivity (data processing, database, internal services), the IGW should be detached.

**Remediation:** Detach and delete the Internet Gateway if this VPC is not intended to have internet connectivity. If the IGW is kept for future use, document the reason and recheck before each audit cycle. If internet connectivity is required, add at least one public subnet with an IGW route and a public-facing resource so the attachment reflects actual use.

---

### CTL.VPC.INCOMPLETE.001

**Complete Data Required for VPC Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

VPC safety cannot be assessed when flow logging status is missing from the snapshot. The extractor must populate network.flow_log.enabled.

**Remediation:** Re-run the extractor with VPC permissions: ec2:DescribeFlowLogs, ec2:DescribeVpcs.

---

### CTL.VPC.IPV6.EGRESSONLY.001

**IPv6 VPC Without Egress-Only Internet Gateway**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

VPC has an IPv6 CIDR block but no egress-only internet gateway. IPv6 has no NAT — every IPv6 address is globally routable by default. With only a standard Internet Gateway attached, IPv6- enabled instances are reachable from the internet on IPv6, not just able to reach out. An egress-only internet gateway is the IPv6 equivalent of a NAT gateway: it permits outbound IPv6 traffic while blocking inbound IPv6 connections from the internet. Without it, the IPv6 surface area is symmetric to the public internet — every IPv6 instance is directly addressable from anywhere.

**Remediation:** Create an egress-only internet gateway in the VPC and update private-subnet route tables so IPv6 default routes (::/0) point to the egress-only IGW rather than the standard IGW. Public IPv6 subnets (those that should accept inbound IPv6, such as the ALB tier) keep the standard IGW route. The distinction parallels the IPv4 NAT pattern: egress-only IGW for private, standard IGW for public.

---

### CTL.VPC.IPV6.NACL.001

**NACL IPv6 Rules Do Not Match IPv4 Restrictions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Network ACL has IPv4 deny or restrict rules but no equivalent IPv6 rules. The NACL filters IPv4 traffic but allows all IPv6 traffic by default. This is the dual-stack parity gap at the NACL layer — equivalent to `CTL.VPC.SG.IPV6.PARITY.001` at the security-group layer. A NACL that denies SSH from 0.0.0.0/0 should also deny SSH from ::/0; otherwise the protection only applies to IPv4 and IPv6 traffic flows through unrestricted.

**Remediation:** For each IPv4 deny or restrict rule, add an equivalent IPv6 rule with the same protocol, port, and action. The IPv6 rule's CIDR is the IPv6 equivalent of the IPv4 CIDR — for example, `0.0.0.0/0` pairs with `::/0`, an IPv4 internal CIDR pairs with the matching IPv6 CIDR. Use NACL rule numbering that keeps each protocol's rules grouped (e.g., 100-199 IPv4, 200-299 IPv6) so dual-stack rules stay obvious to reviewers.

---

### CTL.VPC.IPV6.ROUTE.PUBLIC.001

**Subnet Private on IPv4 but Public on IPv6**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Subnet is private on IPv4 — no 0.0.0.0/0 route to the Internet Gateway — but its route table contains a ::/0 → IGW entry for IPv6. Instances with IPv6 addresses (any instance in a subnet that has an IPv6 CIDR) are directly reachable from the internet despite the subnet being labeled and treated as "private." Operators inspecting route tables for IPv4 IGW routes correctly conclude the subnet has no IPv4 internet exposure, then routinely overlook the IPv6 route. The subnet is private and public simultaneously — depending on which protocol you ask about. The IPv6 route should target the egress-only internet gateway, not the standard IGW.

**Remediation:** Replace the subnet's ::/0 → IGW route with a ::/0 route targeting the VPC's egress-only internet gateway (creating the EIGW first if it does not exist; see `CTL.VPC.IPV6.EGRESSONLY.001`). IPv6 outbound traffic continues to function; inbound IPv6 from the internet is blocked, matching the IPv4-private behavior.

---

### CTL.VPC.NACL.ADMIN.001

**No NACL Ingress from 0.0.0.0/0 to Admin Ports**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Network ACLs must not allow inbound traffic from 0.0.0.0/0 or ::/0 to SSH (22) or RDP (3389) ports. NACLs apply to entire subnets — open admin ports expose all instances.

**Remediation:** Replace the allow rule with a specific CIDR for authorized admin IP ranges using aws ec2 replace-network-acl-entry.

---

### CTL.VPC.NACL.DEFAULT.INUSE.001

**Subnet Uses Default Network ACL**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Subnet is associated with the VPC's default Network ACL, which ships with allow-all rules for both inbound and outbound traffic. Network ACLs are stateless subnet-level filters evaluated before security groups. The default NACL provides no filtering, so security groups become the only network control layer — a misconfigured or overly permissive SG has no NACL safety net. Custom NACLs add defense-in-depth: even if an SG allows SSH from 0.0.0.0/0, a NACL rule denying 0.0.0.0/0:22 at the subnet boundary blocks the traffic.

**Remediation:** Associate the subnet with a custom NACL that mirrors the security-group policy at the subnet boundary: deny known- bad CIDRs, deny admin ports from non-management sources, and allow only the egress destinations required by the subnet's workload. NACLs are stateless, so allow rules must cover both request and response directions explicitly (use AWS documentation's ephemeral-port tables).

---

### CTL.VPC.NACL.RULE.ORDER.001

**NACL Deny Rules Ordered After Allow Rules That Match Same Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

NACL has deny rules with higher rule numbers than allow rules that match the same traffic. NACL rules evaluate in order from lowest rule number to highest; when a rule matches, its action is applied and evaluation stops. A deny rule at rule number 200 for TCP/22 from 0.0.0.0/0 is never reached if rule 100 allows all TCP from 0.0.0.0/0. The deny rule appears to block SSH but has no effect on traffic. This is the NACL-specific "everything appears to work" pattern — an auditor reviewing the rule list sees both an allow-all and a specific deny and may reasonably conclude the deny is effective. It is not.

**Remediation:** Renumber so the deny rule has a lower rule number than the allow rule it is meant to override, or narrow the allow rule so it no longer matches the traffic the deny is targeting. Typical pattern: deny-admin-ports at rule 100, allow-all at rule 200. Do not rely on rule-number spacing habits; always verify order by traffic-flow simulation, not by visual inspection of the rule list.

---

### CTL.VPC.NACL.UNRESTRICTED.001

**Custom NACL Allows All Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

A custom (non-default) Network ACL is associated with subnets but allows all inbound and outbound traffic — the same effect as using the default NACL. Creating a custom NACL implies intent to filter; an allow-all custom NACL is either a misconfiguration or a placeholder from an incomplete deployment. The custom NACL's existence creates the appearance of defense-in-depth — dashboards show "custom NACL: attached" — while providing none of the filtering that justifies the extra moving part.

**Remediation:** Replace the allow-all rules with a minimal deny-and-allow policy for the subnet's workload. At minimum: deny admin ports (22, 3389) from 0.0.0.0/0, deny known-bad CIDR blocks, allow only the egress destinations the workload requires. If the custom NACL is a placeholder for work that never completed, either finish the rule set or delete the NACL and re-associate subnets with the default.

---

### CTL.VPC.NAT.LOGGING.001

**NAT Gateway Does Not Have Flow Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

NAT gateway's ENI does not have flow logs enabled. All outbound internet traffic from private subnets traverses the NAT gateway; without flow logs on the NAT ENI, outbound traffic patterns are invisible — data exfiltration, C2 communication, and unauthorized outbound connections are not recorded. VPC flow logs on subnets capture traffic at the ENI level, but NAT-specific flow logs consolidate the post-NAT egress view that maps back to private source addresses.

**Remediation:** Enable VPC flow logs on the NAT gateway's ENI and direct records to a CloudWatch Logs group or S3 bucket in a logging-dedicated account. Retain per incident-response and compliance requirements (typically one year minimum). Alert on unusual outbound volume, unexpected destinations, and high-entropy payload patterns characteristic of exfiltration and C2.

---

### CTL.VPC.NAT.SINGLEAZ.001

**NAT Gateway Deployed in Single Availability Zone**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CP-7; nist_800_53_r5: CP-7; soc2: A1.2;

NAT gateways for this VPC exist in only one AZ while private subnets exist in multiple AZs. If the NAT's AZ fails, all private subnet instances in other AZs lose outbound internet connectivity — no software updates, no AWS API calls via public endpoints, no outbound communication. Security-critical updates and log shipping stop. Production workloads should have a NAT gateway in each AZ that contains private subnets.

**Remediation:** Deploy one NAT gateway in each AZ that contains private subnets. Update route tables so each private subnet's default route points to the NAT gateway in its own AZ (not a cross-AZ NAT). Using a single shared NAT across AZs also incurs cross-AZ data transfer charges on every outbound connection.

---

### CTL.VPC.NETWORK.FIREWALL.001

**VPC Must Have AWS Network Firewall Deployed**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

VPCs handling sensitive or production traffic should have AWS Network Firewall deployed for stateful packet inspection beyond SG/NACL L3/L4 rules.

**Remediation:** Deploy AWS Network Firewall with inspection rules for the workload's traffic patterns.

---

### CTL.VPC.PEERING.BIDIRECTIONAL.001

**VPC Peering Routes Allow Bidirectional Traffic When Unidirectional Intended**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Both VPCs in the peering connection have route table entries pointing to each other. For many peering use cases (shared services, centralized logging, consumer→producer patterns) only one direction is required — the consumer VPC routes to the shared services VPC, not the reverse. Bidirectional routing doubles the attack surface: a compromise in the shared services VPC can reach into consumer VPCs, and vice versa.

**Remediation:** Review the peering use case. Remove route entries from the side that does not need to initiate connections. If bidirectional traffic is required, document the specific source→destination flows and constrain each side's routes to the specific subnet CIDRs needed.

---

### CTL.VPC.PEERING.CROSSACCOUNT.001

**VPC Peering with Non-Organization Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: AC-4; hipaa: 164.312(e)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

VPC peering connection is established with an AWS account that is not a member of the organization. Network traffic flows at the IP layer between the organization's VPC and an external account's VPC — subject only to security groups and NACLs. The external account's security posture (resources, policies, compromises) is outside organizational control. A compromised external account has direct network access to internal resources via the peering connection. Differs from CTL.RAM.EXTERNAL.001 (resource-level sharing) — peering extends the network boundary itself.

**Remediation:** Delete the peering connection unless a documented business need requires external connectivity. If required, route traffic through an inspection point (Network Firewall, third-party IDS) rather than direct peering, and apply restrictive security groups on subnets reachable via the peering connection.

---

### CTL.VPC.PEERING.DNS.001

**VPC Peering Without DNS Resolution Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** fedramp_moderate: CM-6; nist_800_53_r5: CM-6; soc2: CC7.1;

VPC peering connection does not have DNS resolution enabled. Resources in the peer VPC cannot resolve private DNS names — forcing use of raw IP addresses. Applications that hard-code IPs break when instances are replaced and new IPs are assigned. Low severity — this is an operational/hygiene concern, not a direct security risk — but it signals that the peering connection was configured without attention to its intended use pattern.

**Remediation:** Enable DNS resolution on the peering connection for both VPCs so private DNS names resolve correctly across the boundary. Applications can then reference hosts by DNS name rather than by IP address.

---

### CTL.VPC.PEERING.PENDING.001

**VPC Peering Connection in Pending State**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; soc2: CC7.1;

VPC peering connection is in pending-acceptance state. The peering request was sent but never accepted or rejected. Pending connections indicate forgotten requests — the connection was initiated for a purpose that may no longer exist. If accepted later (by anyone with VPC admin rights in the peer account), the connection activates with whatever routing was configured at creation time, potentially opening a network path no one remembers authorizing.

**Remediation:** Reject the pending peering request. If the connection is still needed, create a fresh request with current routing requirements and document the use case before accepting.

---

### CTL.VPC.PEERING.ROUTES.001

**VPC Peering Route Tables Must Follow Least Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Route table entries for VPC peering connections must reference specific subnet CIDRs within the peered VPC, not the entire VPC CIDR. A route to the full peer VPC CIDR means any resource in the local VPC can reach any resource in the peered VPC — collapsing the network boundary between VPCs that were segmented for a reason. This is the routing-layer equivalent of east-west security group over-permissiveness (CTL.VPC.SG.EASTWEST.001). Cross-environment peering routes — production routing to development or vice versa — are a finding regardless of route specificity, as they violate environment isolation at the routing layer. CIS 5.5 requires that VPC peering route tables follow least access.

**Remediation:** Replace the broad VPC CIDR route with specific subnet CIDR routes that target only the subnets hosting the services that require cross-VPC connectivity. For example, replace a route to 10.1.0.0/16 (entire peer VPC) with a route to 10.1.2.0/24 (specific application subnet). Remove peering routes that cross environment boundaries (production to development) unless explicitly justified.

---

### CTL.VPC.ROUTETABLE.MAIN.PUBLIC.001

**Main Route Table Has Public Route**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

The VPC's main (default) route table has a 0.0.0.0/0 route to an Internet Gateway. Any new subnet created without an explicit custom route-table association inherits the main route table — so every new subnet is public by default. The operator creating the subnet must remember to associate a private route table; omission produces an internet-facing subnet silently. The safe default is a main route table with no IGW route, so subnets are private unless explicitly associated with a public route table.

**Remediation:** Remove the 0.0.0.0/0 → IGW route from the main route table. Create a dedicated "public-subnets" route table with the IGW route and explicitly associate it only with subnets that should be public (ALB, NAT, bastion). New subnets inherit the main route table, so the main route table should represent the safe default (no internet route).

---

### CTL.VPC.ROUTETABLE.ORPHANED.001

**Route Table Not Associated with Any Subnet**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: CM-8; nist_800_53_r5: CM-8; soc2: CC7.1;

Route table exists but is not associated with any subnet, implicit or explicit. The table's routes are inert. Orphaned route tables are a lifecycle signal — the subnet that used this table was deleted but the table itself was left behind. Hygiene accumulation in the VPC layer usually tracks with accumulation in other layers (stale security groups, stale IAM policies).

**Remediation:** Delete the orphaned route table. Add an association-count check to periodic VPC housekeeping so route tables that sit unassociated for longer than a defined threshold are reported and removed. Review neighboring resources (security groups, EIPs) for matching staleness.

---

### CTL.VPC.SEGMENT.BASTION.001

**Bastion Host Has Unrestricted Internal Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: AC-17; hipaa: 164.312(e)(1); nist_800_53_r5: AC-17; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

A bastion or jump host (identified by tag or name containing "bastion"/"jump"/"jumpbox", or an instance with a public IP and SSH ingress from 0.0.0.0/0) has a security group that permits outbound to all internal subnets on management ports (SSH/22, RDP/3389). The bastion is, by design, the bridge between the public internet and the internal network — making it the highest-value lateral-movement target. A compromise of the bastion with unrestricted internal egress yields management-plane access to every instance in the VPC. The bastion's egress should be scoped to specific destination subnets and ports.

**Remediation:** Tighten the bastion SG egress to only the subnets and ports required for legitimate jump-host duties. Examples: SSH only to the application-subnet CIDR, RDP only to the Windows-tier CIDR. Replace the bastion with AWS Systems Manager Session Manager where feasible — it eliminates the bastion entirely and routes through IAM-authenticated SSM rather than SSH. If a bastion remains, keep its instance image patched, log every session to CloudWatch Logs or S3, and enforce MFA on the IAM role that connects.

---

### CTL.VPC.SEGMENT.EASTWEST.001

**Inter-VPC Traffic via Transit Gateway Not Inspected**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Traffic transiting the Transit Gateway between attached VPCs is not routed through a Network Firewall or inspection VPC. Cross- VPC packets flow directly from source VPC to destination VPC without any inspection — no IDS/IPS, no protocol anomaly detection, no domain reputation checks, no logging beyond flow-log metadata. East-west lateral movement between workloads is uninspected. The recommended pattern routes all inter-VPC traffic through a centralized inspection VPC whose Network Firewall enforces stateful policy on every cross-VPC flow.

**Remediation:** Add an inspection VPC attachment to the Transit Gateway. Deploy AWS Network Firewall in the inspection VPC. Update the TGW route tables so inter-VPC default routes target the inspection VPC's attachment, not the destination VPC directly. The inspection VPC firewall then enforces stateful policy on every cross-VPC flow. Validate by confirming non-zero firewall flow logs after the cutover.

---

### CTL.VPC.SEGMENT.ENVMIX.001

**Production and Non-Production Workloads Share Network Path**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Production and non-production (development, staging, testing) resources exist in the same VPC, or in VPCs connected via peering or Transit Gateway with route-table entries that permit cross- environment traffic. Network segmentation between environments is the primary blast-radius control: a compromised low-trust workload in development should not have a network path to production databases. When environments share a VPC or have unrestricted inter-VPC routing, that control is absent. Strengthens `CTL.VPC.ENV.ISOLATION.001` with explicit detection of mixed environments sharing a network path.

**Remediation:** Move non-production workloads to dedicated VPCs and remove any routing between production and non-production VPCs (peering or TGW). If a controlled connection is required (e.g., shared services), terminate it through an inspection VPC with a Network Firewall and tightly scoped routes. Standardize an `Environment` tag with values `production`, `staging`, `development`, `testing` so this control fires reliably; the tag-name and value heuristics are configurable.

---

### CTL.VPC.SEGMENT.LAMBDA.001

**Lambda Function in VPC Has Unrestricted Subnet Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Lambda function configured with VPC access has a security group that permits outbound to all subnets in the VPC. The Lambda ENI can reach every resource in every subnet — databases, caches, internal APIs, management interfaces. Lambda functions should have egress restricted to the specific subnets and ports they require; the function code is small, the surface it should reach is well-defined, and unrestricted egress allows a compromised function to pivot anywhere in the VPC.

**Remediation:** Replace the Lambda SG egress with explicit destination rules: only the CIDRs and ports the function actually calls. For an RDS-querying function, allow outbound to the DB subnet CIDR on the database port only. For a function calling internal APIs, allow outbound to the API subnet CIDR on the application port only. If the function calls AWS services privately, prefer interface VPC endpoints over broad outbound rules.

---

### CTL.VPC.SEGMENT.TIERING.001

**Subnet Mixes Web, Application, and Data-Tier Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Web-facing resources (load balancers, web servers), application logic (app servers, Lambda ENIs, ECS tasks), and data stores (RDS, ElastiCache, Redshift) share the same subnet. With no subnet tier separation, security groups become the only network control — there is no NACL boundary between tiers. A compromise at any tier reaches every other tier on the same broadcast domain at the network layer; only SG rules stand in the way. Tier separation puts web in public subnets, application in private subnets, and data in private subnets associated with database-only NACLs.

**Remediation:** Reorganize subnets so each tier has dedicated subnets: public subnets for ALBs/NLBs/bastions, private subnets for application workloads, isolated private subnets for databases (no IGW/NAT route). Migrate existing resources tier-by-tier; use database snapshots and Lambda blue/green to minimize downtime. After tier separation, apply NACLs that mirror each tier's intended traffic boundaries.

---

### CTL.VPC.SG.CIDR.BROAD.001

**Security Group Rule Uses Overly Broad CIDR**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Security group inbound rule uses a CIDR block broader than /16 (65,536 addresses) that is not 0.0.0.0/0 (caught by existing controls). A /8 CIDR includes approximately 16 million IP addresses. Unless the rule references a known AWS service CIDR or organizational network, the range is broader than needed.

**Remediation:** Replace broad CIDR ranges with specific subnets. A /24 (256 addresses) is precise. A /8 (16M addresses) is almost certainly too broad.

---

### CTL.VPC.SG.DEFAULT.001

**Default Security Group Must Restrict All Traffic**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.4; cis_aws_v3.0: 5.4; fedramp_moderate: AC-4; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

The default VPC security group should not allow any inbound or outbound traffic. Resources should use custom security groups with explicit rules instead of relying on the default group.

**Remediation:** Remove all inbound and outbound rules from the default security group. Assign custom security groups to all resources.

---

### CTL.VPC.SG.DEFAULT.INUSE.001

**Default Security Group Attached to Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.4; nist_800_53_r5: SC-7; soc2: CC6.6;

The VPC default security group is attached to one or more resources. The default SG allows all traffic between resources attached to it (inbound from same SG) and all outbound traffic. Resources should use purpose-built security groups with explicit rules. Strengthens CTL.VPC.SG.DEFAULT.001 which checks whether the default SG has rules — this control checks whether it is actually attached.

**Remediation:** Move resources to purpose-built security groups with explicit rules. The default SG should have no attached resources.

---

### CTL.VPC.SG.EASTWEST.001

**Security Groups Must Not Allow Unrestricted Access Between Internal Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Security groups on private resources must not allow inbound traffic on application ports from broad internal CIDR ranges or all-port rules from internal sources. East-west over-permissiveness enables lateral movement — a compromised service in the source range inherits access to every destination that grants broad internal access. This is distinct from CTL.VPC.SG.UNRESTRICTED.001 which detects north-south exposure (0.0.0.0/0). Specific conditions: inbound rules from CIDRs broader than /28 (16 addresses), rules referencing the entire VPC CIDR range, or all-port rules from any internal source. The /28 threshold accommodates small dedicated subnets while flagging rules that effectively open access to large internal populations. NSA/CISA advisory AA23-278A identifies flat internal networks as one of the ten most exploited misconfigurations — attackers consistently use over-permissive east-west rules for lateral movement from low-privilege footholds to high-value targets.

**Remediation:** Replace broad CIDR source rules with specific security group references that identify the exact source service. Replace all-port internal rules with rules specifying only the ports the service relationship requires. For database security groups, restrict inbound to the specific application server security group on the database port only. Verify no rule references the entire VPC CIDR range as a source.

---

### CTL.VPC.SG.EGRESS.001

**Security Groups Must Not Allow Unrestricted Egress**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups must not allow all outbound traffic to 0.0.0.0/0 on all ports. Unrestricted egress enables data exfiltration, command-and-control communication, and lateral movement to external attacker infrastructure. While most organizations currently allow all egress by default, restricting outbound traffic to required ports and destinations is a critical APT hardening measure.

**Remediation:** Replace the default allow-all egress rule with specific outbound rules for required ports (443 for HTTPS, 53 for DNS, etc.) and destinations. Use VPC endpoints for AWS service traffic to avoid internet egress entirely.

---

### CTL.VPC.SG.EGRESS.DNS.001

**Security Group Allows DNS Egress to Internet**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group allows UDP/TCP port 53 outbound to 0.0.0.0/0 instead of restricting DNS to internal resolvers or VPC DNS (169.254.169.253). Unrestricted DNS egress enables DNS tunneling — data exfiltration encoded in DNS queries to attacker-controlled domains.

**Remediation:** Restrict DNS egress to the VPC DNS resolver (169.254.169.253) or Route53 Resolver endpoints. Remove rules allowing port 53 to 0.0.0.0/0.

---

### CTL.VPC.SG.EGRESS.EXFIL.001

**Security Groups Must Restrict Egress on Data Exfiltration Ports**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups must not allow unrestricted outbound traffic to 0.0.0.0/0 on ports commonly used for data exfiltration (443/HTTPS, 53/DNS, 80/HTTP) even when other ports are blocked. Exfiltration traffic hides in standard web and DNS protocols.

**Remediation:** Restrict egress to specific destination CIDRs where possible. For DNS (53), route through a DNS firewall or VPC resolver endpoint. For HTTPS (443), consider VPC endpoint routes instead of internet egress. Note: blocking 443/53 outbound breaks most applications — this control flags for awareness, not hard block.

---

### CTL.VPC.SG.GHOST.001

**Security Group Rules Must Not Reference Deleted Security Groups**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6; soc2: CC6.1;

Security group inbound and outbound rules must not reference other security groups that have been deleted. Orphaned SG references clutter the rule set, confuse security audits, and mask the effective rule set. SG IDs are system-generated and not reusable, so the rule effectively permits nothing — this is a governance finding, not an exploitable vulnerability.

**Remediation:** Remove orphaned rules referencing non-existent security group IDs.

---

### CTL.VPC.SG.HIGHPORTS.001

**Security Group Allows High-Risk Service Ports from Internet**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group allows inbound traffic from 0.0.0.0/0 on ports associated with high-risk services that should never be internet- exposed: 445 (SMB), 135 (RPC), 139 (NetBIOS), 1900 (SSDP), 11211 (Memcached), 9200/9300 (Elasticsearch), 6379 (Redis), 27017 (MongoDB), 5601 (Kibana), 2375/2376 (Docker), 10250 (Kubelet).

**Remediation:** Remove inbound rules allowing internet access on high-risk ports (445, 135, 139, 6379, 9200, 27017, 2375, 10250, 5601, 11211, 1900). These services should never be internet-exposed.

---

### CTL.VPC.SG.ICMP.001

**Security Group Allows All ICMP from Internet**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group allows all ICMP types from 0.0.0.0/0. ICMP includes not just ping (type 8) but also redirect (type 5 — route manipulation), timestamp (type 13 — system fingerprinting), and address mask (type 17 — network mapping). Allowing all ICMP types enables network reconnaissance and potential route manipulation.

**Remediation:** Restrict ICMP to type 8 (echo request) only if ping is needed. Remove rules allowing all ICMP types from 0.0.0.0/0.

---

### CTL.VPC.SG.IPV6.001

**No Security Group Ingress from ::/0 to Admin Ports**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.3; fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security groups must not allow inbound SSH (22) or RDP (3389) from ::/0 (IPv6 any). IPv6 open admin ports are equally dangerous as IPv4 and are often overlooked during security reviews.

**Remediation:** Revoke the IPv6 ingress rule: aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,Ipv6Ranges=[{CidrIpv6=::/0}]

---

### CTL.VPC.SG.IPV6.EGRESS.001

**Security Group Has IPv6 Egress to All Destinations**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Security group allows all IPv6 egress to ::/0. If IPv4 egress is restricted but IPv6 egress is open, data exfiltration routes through IPv6 — bypassing IPv4 egress controls entirely.

**Remediation:** Restrict IPv6 egress to required destinations. If IPv4 egress is restricted, ensure IPv6 egress has equivalent restrictions.

---

### CTL.VPC.SG.IPV6.PARITY.001

**Security Group Has IPv4 Restrictions But Missing IPv6 Equivalents**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Security group has inbound rules restricting IPv4 access (specific CIDRs, not 0.0.0.0/0) but no equivalent IPv6 restrictions — or has ::/0 (all IPv6) allowed on the same ports. IPv6 addresses are publicly routable by default and the missing IPv6 rules mean the IPv4 restriction is incomplete.

**Remediation:** Add IPv6 rules that match the IPv4 restrictions. For every IPv4 CIDR restriction, add an equivalent IPv6 rule or explicitly deny ::/0.

---

### CTL.VPC.SG.PORTRANGE.001

**Security Group Rule Uses Broad Port Range**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Security group rule allows a range of more than 100 ports (e.g., 1024-65535, 8000-9000) instead of a specific port. Broad port ranges expose more services than intended — the range may include ports for services the team does not know are running on the instance.

**Remediation:** Replace broad port ranges with specific port rules. A rule for port 8080 is safer than a range 8000-9000 which exposes all services in that range.

---

### CTL.VPC.SG.RECUR.001

**Security Group Must Not Have Unrestricted Ingress Appear Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-5; hipaa: 164.312(e)(1); nist_800_53_r5: IR-5; pci_dss_v4.0: 12.10; soc2: CC7.1;

Security group has had unrestricted ingress (0.0.0.0/0 or ::/0) added, removed, and added again more than twice in 30 days. Security group rules are not accidental — adding a rule is a deliberate API call. Repeated re-addition after removal indicates either a broken change process or an attacker re-enabling their access path after detection.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.VPC.SG.UNRESTRICTED.001

**Security Groups Must Not Allow Unrestricted Ingress**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 5.2; cis_aws_v3.0: 5.2; fedramp_moderate: AC-4; hipaa: 164.312(e)(1); nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Security group rules must not allow ingress from 0.0.0.0/0 on sensitive ports (SSH, RDP, database). Unrestricted ingress exposes services to the entire internet.

**Remediation:** Restrict ingress rules to specific CIDR blocks or security group references. Remove 0.0.0.0/0 and ::/0 from ingress rules on ports 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL).

---

### CTL.VPC.SUBNET.AUTOPUBLIC.001

**Subnet Auto-Assigns Public IP Addresses**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Subnet has `MapPublicIpOnLaunch` enabled. Every resource launched in this subnet automatically receives a public IP address — without the launcher explicitly requesting one. A developer launching an EC2 instance, an ECS task, or a Lambda ENI in this subnet may not know it becomes internet-facing. Combined with a subnet route to an Internet Gateway and a permissive security group (often the default), resources become reachable from the internet without any explicit decision to make them public.

**Remediation:** Disable `MapPublicIpOnLaunch` on the subnet. Require resources that need a public IP to request one explicitly at launch, which makes the exposure decision visible in the launch API call and in IaC diffs. For subnets that are genuinely public (ALB ingress, bastions), consider a naming convention and tag that makes the public-facing role explicit and pair it with tight security groups.

---

### CTL.VPC.SUBNET.PRIVATEDB.001

**Database Subnet Has Route to Internet Gateway**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.1; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

A subnet containing RDS instances, ElastiCache clusters, or Redshift clusters has a route table with 0.0.0.0/0 pointing to an Internet Gateway. The database subnet is effectively public at the network layer — the internet route path exists. A single security group rule change is the gap between current-state safety and direct internet exposure of the database. Complements `CTL.RDS.PUBLIC.001` (which checks the RDS instance's `PubliclyAccessible` setting). Database hosts should live in subnets where an internet route is structurally absent.

**Remediation:** Move the database resources to a subnet whose route table has no IGW route. If the current subnet is shared between databases and public workloads, split it: create a dedicated private subnet group for databases (RDS subnet group, ElastiCache subnet group) and migrate the instances. Do not rely on security group rules alone to contain databases; the network path should not exist in the first place.

---

### CTL.VPC.TGW.ATTACHMENT.ISOLATED.001

**Transit Gateway Has Attachment From Isolated VPC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; soc2: CC6.6;

A VPC whose tags or name signal network isolation (keywords such as "isolated", "sandbox", "quarantine", "restricted") is attached to the Transit Gateway. The TGW provides a network path to and from a VPC that was intended to stand apart. Isolation is a statement about blast-radius containment — attaching the VPC to a shared hub negates that statement regardless of route-table configuration. The keyword list is a heuristic and is configurable per deployment.

**Remediation:** Detach the isolated VPC from the Transit Gateway. If connectivity is actually required, remove the "isolated"/"sandbox"/"quarantine" markers from the VPC's tags and name and document the connection rationale — the markers should reflect actual posture. Do not leave mismatched metadata in place.

---

### CTL.VPC.TGW.BLACKHOLE.001

**Transit Gateway Has Blackhole Routes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** hygiene
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: CM-6; nist_800_53_r5: CM-6; soc2: CC7.1;

Transit Gateway route table contains blackhole routes — destinations where traffic is silently dropped with no error returned. Blackhole routes typically arise when a VPC attachment is deleted but the route persists, or when a route is intentionally added to block a CIDR. Unintentional blackholes follow the "everything appears to work" failure pattern: applications experience timeouts rather than errors, no ICMP unreachable is returned, nothing is logged for the dropped traffic. Troubleshooting is difficult because the network layer reports no failure.

**Remediation:** Audit each blackhole route. For routes that reference deleted attachments, delete the stale route so traffic falls through to the correct next hop (or returns a routing error, which is troubleshootable). For intentional blocks, document the reason and consider moving the block to a security group or Network Firewall rule where it will produce a log entry.

---

### CTL.VPC.TGW.FLOWLOGS.001

**Transit Gateway Flow Logs Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Transit Gateway flow logs are not enabled. Cross-VPC traffic transiting through the TGW is not recorded. The TGW is the central hub for inter-VPC traffic — if flow logs are enabled on individual VPCs but not on the TGW itself, lateral-movement traffic between VPCs is invisible. Per-VPC flow logs capture traffic that enters and exits a VPC, but they do not show the TGW-internal routing decisions or traffic that traverses multiple VPCs via the TGW. Flow logs at the hub are required for forensics, anomaly detection, and incident response on cross-VPC flows.

**Remediation:** Enable flow logs on the Transit Gateway, sending records to a CloudWatch Logs group or S3 bucket in a logging-dedicated account. Retain logs per your incident response and compliance requirements (typically 1 year minimum). Correlate TGW flow logs with VPC flow logs to trace cross-VPC traffic end to end.

---

### CTL.VPC.TGW.PROPAGATION.001

**Transit Gateway Route Propagation From VPN or Direct Connect**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.2; soc2: CC6.6;

Transit Gateway has route propagation enabled from VPN or Direct Connect attachments. Routes from on-premises or external networks are automatically propagated into TGW route tables. An on-premises network that is compromised or misconfigured can announce routes for arbitrary CIDRs — including AWS service IP ranges — and redirect traffic through attacker-controlled infrastructure. BGP route injection is the attack path. Static routes constrained to known on-premises CIDRs are the safe pattern.

**Remediation:** Disable route propagation from VPN/Direct Connect attachments on the TGW route table. Configure static routes with explicit destination CIDRs for the on-premises networks you need to reach. Audit existing propagated routes before removal to identify any that are relied on.

---

### CTL.VPC.TGW.ROUTING.ALLTOALL.001

**Transit Gateway Route Table Allows All-to-All Communication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Transit Gateway route table has routes that allow every attached VPC to communicate with every other attached VPC. The TGW becomes a flat network bridge — no segmentation between workloads. Production, development, staging, and shared services VPCs all reach each other at the network layer. A compromised instance in any attached VPC has a direct path to every other attached VPC, defeating the blast-radius isolation that separate VPCs were created to enforce. Segmented TGW route tables (one per security zone, associated only with the VPCs in that zone) are the correct pattern.

**Remediation:** Replace the single shared route table with per-zone route tables. Associate each VPC attachment with the route table for its zone and configure propagation only between attachments that must communicate. Audit existing traffic to identify which flows are legitimate before enforcing new segmentation.

---

### CTL.VPC.VPN.ENCRYPTION.WEAK.001

**VPN Connection Uses Weak Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

Site-to-site VPN tunnel uses encryption below AES-256 or integrity hashing below SHA-256. Phase 1 (IKE) or Phase 2 (IPsec) parameters include deprecated algorithms (DES, 3DES, AES-128, SHA-1, MD5). AWS permits customer-configured tunnel options that may include weak algorithms for backward compatibility with legacy on-premises equipment — compatibility should not override cryptographic strength for traffic that carries production data.

**Remediation:** Reconfigure the VPN connection's tunnel options to require AES-256 for encryption and SHA-256 (or stronger) for integrity. Use IKEv2 rather than IKEv1. Replace DH Group 2/5 with Group 14 or higher. Coordinate with the on-premises peer to match parameters; if the peer does not support these algorithms, upgrade the peer device rather than weaken AWS-side configuration.

---

### CTL.VPC.VPN.LOGGING.001

**VPN Connection Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Site-to-site VPN tunnel logging is not enabled. Connection events (tunnel UP/DOWN transitions, IKE negotiation failures, authentication attempts, rekey events) are not recorded. VPN connectivity failures, configuration drift, and attack attempts (IKE brute force, replay attacks, identity spoofing) are invisible to security operations.

**Remediation:** Enable tunnel logging on each tunnel of the VPN connection, sending records to a CloudWatch Logs group in a logging-dedicated account. Retain logs per incident-response and compliance requirements (typically one year minimum). Alert on repeated IKE failures and unexpected tunnel state changes.

---

### CTL.VPC.VPN.PSK.001

**VPN Uses Pre-Shared Key Instead of Certificate Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: IA-5; hipaa: 164.312(d); nist_800_53_r5: IA-5; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

VPN tunnel uses pre-shared key (PSK) authentication instead of certificate-based (PKI) authentication. PSKs are static shared secrets configured on both endpoints — widely readable in config files, shared across multiple administrators, and not rotated automatically. If the PSK is compromised, all historical and future traffic protected by that key is at risk. Certificate-based authentication binds trust to a cryptographic identity that can be rotated and revoked.

**Remediation:** Migrate the VPN to certificate-based authentication. Issue a certificate for the on-premises device from an internal or managed CA, configure the customer gateway with certificate authentication, and remove the PSK. If certificate authentication is not feasible, rotate the PSK on a schedule, restrict its storage to a secrets manager, and limit the admins who hold it.

---

### CTL.VPC.VPN.TUNNEL.DOWN.001

**VPN Tunnel Not in UP State**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** cis_aws_v3.0: 5.5; fedramp_moderate: CP-7; nist_800_53_r5: CP-7; soc2: A1.2;

One or both VPN tunnels are not in UP state. AWS provisions two tunnels per site-to-site VPN connection for high availability. With one tunnel down, the VPN operates on a single tunnel with no failover — a single point of failure for hybrid connectivity. With both tunnels down, the VPN is non-functional and traffic either fails outright or silently falls back to internet paths (which may be unencrypted).

**Remediation:** Identify the root cause — check the on-premises peer's status, verify pre-shared keys or certificates, confirm routing, and review CloudWatch metrics for IKE or tunnel-state transitions. Restore both tunnels to UP. For persistent single-tunnel failures, open a support case with AWS and the on-premises vendor simultaneously.

---


# Control Reference — NETFIREWALL

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.NETFIREWALL.DEFAULT.FRAG.001

**Network Firewall Must Not Pass Fragmented Packets by Default**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall stateless default action for fragmented packets must be aws:drop or aws:forward_to_sfe. Fragmented packets are a common evasion technique — passing them uninspected bypasses deep packet inspection.

**Remediation:** Set StatelessFragmentDefaultActions to aws:drop or aws:forward_to_sfe.

---

### CTL.NETFIREWALL.DEFAULT.FULL.001

**Network Firewall Must Not Pass Full Packets by Default**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall stateless default action for full packets must be aws:drop or aws:forward_to_sfe, not aws:pass. Default PASS means all traffic not matching stateless rules flows uninspected.

**Remediation:** Set StatelessDefaultActions to aws:drop or aws:forward_to_sfe.

---

### CTL.NETFIREWALL.DELETEPROT.001

**Network Firewall Must Have Deletion Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Network Firewalls must enable deletion protection to prevent accidental or malicious removal. Deleting the firewall removes all traffic inspection from the VPC.

**Remediation:** Enable deletion protection on the firewall.

---

### CTL.NETFIREWALL.LOG.001

**Network Firewall Must Have Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Network Firewalls must have stateful engine logging configured with at least one log type (FLOW, ALERT, or TLS) and an active destination. Without logging, inspected traffic generates no audit trail.

**Remediation:** Configure logging with FLOW, ALERT, or TLS log types.

---

### CTL.NETFIREWALL.MODE.001

**Network Firewall Stateful Rules in Alert-Only Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(c)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Network Firewall stateful engine default action is configured as ALERT (or the default rule order has stateful rules producing alert-only matches). The firewall detects threats, logs them, and lets the traffic through. Alert-only mode is appropriate during initial rule validation — typically one to two weeks while tuning false positives — but persistence beyond that window represents a deployment that was never completed. In production configurations, stateful default action should be DROP or REJECT so that rule matches block traffic, not merely record it.

**Remediation:** Switch the stateful engine's default action from ALERT to DROP (or REJECT where TCP RST is appropriate). If rule validation is still in progress, set an explicit deadline — record the date when the alert-mode deployment began and commit to transitioning to DROP within two weeks. Alert-mode dashboards and runbooks should clearly label the deployment as pre-enforcement.

---

### CTL.NETFIREWALL.MULTIAZ.001

**Network Firewall Must Be Deployed Across Multiple AZs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

Network Firewalls must be deployed with subnet mappings in multiple Availability Zones. Single-AZ deployment means an AZ outage removes all traffic inspection.

**Remediation:** Add subnet mappings in additional AZs.

---

### CTL.NETFIREWALL.POLICY.RULEGROUP.001

**Network Firewall Policy Must Have Rule Groups Associated**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Network Firewall policies must have at least one stateful or stateless rule group associated. An empty policy means the firewall sits in the network path without evaluating any rules — all traffic is handled by the default action alone.

**Remediation:** Associate stateful and/or stateless rule groups with the policy.

---

### CTL.NETFIREWALL.ROUTING.001

**Network Firewall Not in Traffic Path**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

AWS Network Firewall is deployed but no route tables direct traffic through the firewall endpoints. The firewall appears active, its policy and rule groups are configured, and logs may show zero events — but no traffic is actually being inspected. The firewall sits in the VPC as an unreferenced endpoint while packets flow around it via route tables that bypass it. This is the network security equivalent of a smoke detector that is installed but not connected to power. Dashboards show the detector; nothing it is supposed to watch actually reaches it.

**Remediation:** Update the route tables for each subnet whose traffic should be inspected. For ingress inspection, the Internet Gateway route table (or the relevant subnet route tables) must route 0.0.0.0/0 to the firewall endpoint in the matching AZ. For egress inspection, protected subnets' route tables must route default traffic to the firewall endpoint. Validate by confirming non-zero flow logs on the firewall after the change. Absence of traffic should be the exception, not the default.

---

### CTL.NETFIREWALL.RULEGROUP.ENCRYPT.001

**Network Firewall Rule Group Must Use Customer-Managed KMS Key**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

Network Firewall rule groups should encrypt their configuration at rest with a customer-managed KMS key. Without CMK encryption the rule group data is encrypted with an AWS-managed key, which provides no key-policy control over who can read the rule definitions and no CloudTrail visibility into decrypt operations.

**Remediation:** Recreate the rule group with an EncryptionConfiguration specifying Type CUSTOMER_KMS and the KMS key ARN. Existing rule groups cannot be updated in place — export the rules, delete, and recreate.

---

### CTL.NETFIREWALL.RULES.PERMISSIVE.001

**Network Firewall Rule Group Contains Allow-All Rule**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

A Network Firewall rule group contains a rule that allows all traffic (action `pass`, protocol `any`, source `any`, destination `any`). The rule group exists and is associated with the policy, but a catch-all pass rule short-circuits inspection for every packet that reaches it. This is the NF equivalent of a WAF that runs in count-only mode with a bypass rule — the control exists, evaluates packets, and does nothing with them. Distinct from `CTL.NETFIREWALL.DEFAULT.FULL.001` (which checks the stateless default action); this control checks for explicit allow-any rules inside rule groups.

**Remediation:** Remove the allow-any rule from the rule group. If a broad allow is needed for legitimate high-volume traffic, scope it explicitly (specific CIDRs, specific ports, specific protocols) rather than using any/any/any. Audit the rule group's rule order: pass-any rules are particularly dangerous at the top of a group because they bypass every subsequent rule.

---

### CTL.NETFIREWALL.RULES.STATEFUL.001

**Network Firewall Has No Stateful Rule Groups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.2.1; soc2: CC6.6;

Network Firewall's associated policy has only stateless rules (or no rules at all). Stateless rules evaluate each packet in isolation — no connection tracking, no TCP session awareness, no stream reassembly, no application-layer visibility. Stateful rules add connection state, session lifecycle awareness, and Suricata-style content inspection (protocol anomaly detection, IDS/IPS signatures). A firewall with only stateless rules is a packet filter with richer syntax, not a connection-aware firewall. Complements `CTL.NETFIREWALL.POLICY.RULEGROUP.001` (which checks that at least one rule group of any type is associated); this control checks for stateful coverage specifically.

**Remediation:** Associate at least one stateful rule group with the firewall policy. Start with AWS managed threat-signature rule groups (ThreatSignaturesEmergingThreats, ThreatSignaturesBotnet, ThreatSignaturesMalware) and add domain-allowlist or -denylist stateful rules for your workload's traffic pattern. Keep stateless rules for high-volume allow/deny of well-known traffic; use stateful rules for everything that requires session or content awareness.

---

### CTL.NETFIREWALL.TLS.001

**Network Firewall TLS Inspection Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; hipaa: 164.312(e)(1); nist_800_53_r5: SI-4; pci_dss_v4.0: 11.5.1; soc2: CC7.1;

Network Firewall does not have TLS inspection enabled. Encrypted traffic (HTTPS, TLS) passes through the firewall with only connection-metadata visibility — source and destination IPs, ports, SNI hostnames. The firewall cannot inspect the encrypted payload: URL paths, request bodies, response content, uploaded files. Malware delivered via HTTPS, command-and-control communication over HTTPS, and data exfiltration inside TLS sessions bypass content inspection entirely. TLS inspection is a defense-in-depth measure with operational tradeoffs (certificate management, performance impact, privacy and compliance considerations for decrypting user traffic) — not every environment should enable it, but every environment should document a conscious decision about it.

**Remediation:** Enable TLS inspection on the firewall policy. Provision an ACM certificate for the firewall's interception role and configure the TLS inspection configuration with the traffic scope (source/destination CIDRs, SNI patterns). Exclude flows where decryption is contractually or legally inappropriate (employee personal services, healthcare portals, banking, etc.) via an allowlist. If TLS inspection is intentionally not used, document the decision and the compensating controls (endpoint protection, egress allowlisting by domain, application-layer logging on the destination).

---


# Control Reference — CISCO

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CISCO.ACL.EGRESS.001

**Egress Filtering Must Be Applied**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.2.1; nist_800_53_r5: SC-7;

Cisco IOS devices must have egress filtering applied on external interfaces. Without egress filtering, the device forwards traffic with any source address including spoofed and RFC 1918 addresses. An attacker on the internal network can send packets with forged source addresses to participate in reflected DDoS attacks, evade source-based logging and tracing, or exfiltrate data in a way that cannot be traced back to the originating host.

**Remediation:** Apply egress ACLs to external interfaces permitting only legitimate source address ranges. Run: interface <external-interface> ip access-group <egress-acl> out Verify with: show ip access-lists

---

### CTL.CISCO.ACL.VTY.001

**VTY Lines Must Have ACL Applied**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.1.1; nist_800_53_r5: AC-3;

All VTY lines on Cisco IOS devices must have an access-class ACL applied to restrict remote management access. Without an ACL on VTY lines, any IP address that can reach the device can attempt SSH or Telnet connections. An attacker from any network position can attempt credential brute-force attacks against the management interface. VTY access should be restricted to authorized management networks only.

**Remediation:** Apply an access-class ACL to all VTY lines. Run: line vty 0 15 access-class <acl-name> in Verify with: show running-config | section line vty

---

### CTL.CISCO.AUTH.AAA.001

**AAA New-Model Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.2.1; nist_800_53_r5: IA-2;

Cisco IOS devices must have AAA new-model enabled. Without AAA new-model, the device falls back to line-based authentication which cannot enforce centralized authentication, authorization, or accounting policies. An attacker who compromises a local line password gains full access with no audit trail and no ability to enforce per-user access controls.

**Remediation:** Enable AAA new-model. Run: aaa new-model Verify with: show running-config | include aaa new-model

---

### CTL.CISCO.AUTH.ACCOUNTING.001

**AAA Accounting Exec Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.5; nist_800_53_r5: AU-2;

Cisco IOS devices must have AAA accounting for exec sessions configured. Without exec accounting, there is no record of who accessed the device, when sessions started and stopped, or what privilege level was used. An attacker can access the device and perform reconnaissance or configuration changes with no audit trail for incident response or forensic analysis.

**Remediation:** Configure AAA accounting for exec sessions. Run: aaa accounting exec default start-stop group tacacs+ Verify with: show running-config | include aaa accounting exec

---

### CTL.CISCO.AUTH.ENABLE.001

**Enable Secret Must Be Configured**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.1.1; nist_800_53_r5: IA-5;

Cisco IOS devices must use enable secret instead of enable password. The enable password command stores the password using a weak reversible cipher (Type 7) that is trivially decoded. Enable secret uses a one-way hash (MD5 or scrypt) that cannot be reversed. An attacker with read access to the running configuration can decode Type 7 passwords instantly using publicly available tools.

**Remediation:** Configure enable secret and remove enable password. Run: enable secret <strong-password> no enable password Verify with: show running-config | include enable

---

### CTL.CISCO.AUTH.LOGIN.001

**AAA Authentication Login Must Be Configured**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.2.2; nist_800_53_r5: IA-2;

Cisco IOS devices must have AAA authentication login configured. Without an explicit authentication login method list, the device uses default line authentication which typically accepts a single shared password. This prevents per-user accountability and allows any user with the shared password to access the device without individual identification.

**Remediation:** Configure AAA authentication login. Run: aaa authentication login default group tacacs+ local Verify with: show running-config | include aaa authentication login

---

### CTL.CISCO.AUTH.SVCENC.001

**Service Password-Encryption Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_cisco_ios_17: 1.1.2; nist_800_53_r5: IA-5;

Cisco IOS devices must have service password-encryption enabled. Without this service, passwords in the running and startup configuration are stored in cleartext. Anyone with read access to the configuration file — through SNMP, TFTP backup, or shoulder surfing — can immediately read all passwords including line passwords and username passwords.

**Remediation:** Enable service password-encryption. Run: service password-encryption Verify with: show running-config | include service password

---

### CTL.CISCO.BGP.AUTH.001

**BGP Neighbors Must Use Authentication**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.1; nist_800_53_r5: SC-8;

All BGP neighbor sessions on Cisco IOS devices must be configured with MD5 authentication. Without authentication, an attacker who can reach the BGP TCP port (179) can establish a peer session and inject arbitrary routes. This enables traffic hijacking, black-hole attacks, and man-in-the-middle interception of traffic destined for any prefix the attacker advertises. BGP route injection can redirect traffic at internet scale.

**Remediation:** Configure MD5 authentication for all BGP neighbors. Run: router bgp <asn> neighbor <ip> password <secret> Verify with: show ip bgp neighbors | include password

---

### CTL.CISCO.BGP.FILTERIN.001

**BGP Inbound Route Filtering Must Be Applied**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.2; nist_800_53_r5: SC-7;

All BGP neighbors on Cisco IOS devices must have inbound route filtering configured. Without inbound filters, the device accepts any route advertised by a peer including routes for prefixes the peer has no authority to announce. An attacker who compromises a peer or establishes an unauthorized session can inject routes for any prefix, redirecting traffic through attacker-controlled infrastructure for interception or denial of service.

**Remediation:** Apply inbound prefix-list or route-map filters to all BGP neighbors. Run: router bgp <asn> neighbor <ip> prefix-list <name> in Verify with: show ip bgp neighbors | include filter

---

### CTL.CISCO.BGP.FILTEROUT.001

**BGP Outbound Route Filtering Must Be Applied**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.1.3; nist_800_53_r5: SC-7;

All BGP neighbors on Cisco IOS devices must have outbound route filtering configured. Without outbound filters, the device may advertise routes for prefixes it should not announce, including internal network prefixes, default routes, or prefixes learned from other peers. This can cause route leaks that redirect traffic through unintended paths, expose internal network topology, or create routing loops that cause denial of service.

**Remediation:** Apply outbound prefix-list or route-map filters to all BGP neighbors. Run: router bgp <asn> neighbor <ip> prefix-list <name> out Verify with: show ip bgp neighbors | include filter

---

### CTL.CISCO.HSRP.AUTH.001

**HSRP Must Use Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.3.1; nist_800_53_r5: SC-8;

All HSRP groups on Cisco IOS devices must be configured with authentication. Without HSRP authentication, an attacker on the local network segment can send crafted HSRP hello packets with a higher priority to become the active gateway. This redirects all default gateway traffic through the attacker's machine, enabling man-in-the-middle interception of all traffic leaving the subnet including credentials, session tokens, and sensitive data.

**Remediation:** Configure HSRP authentication for all groups. Run: interface <interface> standby <group> authentication md5 key-string <secret> Verify with: show standby | include authentication

---

### CTL.CISCO.INTF.DIRBROADCAST.001

**Directed Broadcast Must Be Disabled on Interfaces**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.3.1; nist_800_53_r5: SC-7;

Cisco IOS devices must have IP directed broadcast disabled on all interfaces. Directed broadcasts allow a remote host to send a packet to the broadcast address of a subnet, which the router then converts to a layer 2 broadcast. This is the basis of the Smurf attack where an attacker sends ICMP echo requests to a directed broadcast address with a spoofed source, causing all hosts on the subnet to respond to the victim, creating massive amplification.

**Remediation:** Disable directed broadcast on all interfaces. Run: interface <interface> no ip directed-broadcast Verify with: show running-config | include directed-broadcast

---

### CTL.CISCO.MGMT.BANNER.001

**Login Banner Must Be Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.1.1; nist_800_53_r5: AC-8;

A login banner must be configured on Cisco IOS devices. A login banner provides legal notice to anyone attempting to access the device. Without a banner, unauthorized access attempts may not be prosecutable in some jurisdictions because the attacker can claim there was no indication the system was private or that access was restricted. The banner should warn that unauthorized access is prohibited and that activity may be monitored.

**Remediation:** Configure a login banner on the device. Run: banner login ^ Unauthorized access is prohibited. All activity is monitored. ^ Verify with: show banner login

---

### CTL.CISCO.MGMT.HTTP.001

**HTTP Server Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.1; nist_800_53_r5: CM-7;

The HTTP server must be disabled on Cisco IOS devices. The IOS HTTP server provides a web-based management interface that transmits credentials and configuration data in cleartext. An attacker on the network path can intercept administrator credentials, session tokens, and device configuration. The HTTP server has also been the target of multiple IOS vulnerabilities including remote code execution. If web-based management is required, HTTPS must be used instead.

**Remediation:** Disable the HTTP server on the device. Run: no ip http server Verify with: show ip http server status If web management is required, enable HTTPS instead with ip http secure-server.

---

### CTL.CISCO.MGMT.SNMP.001

**SNMP Version Must Be 3**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.1; nist_800_53_r5: SC-8;

Cisco IOS devices must use SNMP version 3. SNMP v1 and v2c transmit community strings in cleartext and provide no authentication or encryption. An attacker with network access can capture community strings and gain read or read-write access to the device MIB. SNMP v3 provides authentication (AuthNoPriv) and encryption (AuthPriv) protecting both credentials and management data in transit.

**Remediation:** Configure SNMP v3 with authentication and privacy. Run: snmp-server group <group> v3 priv snmp-server user <user> <group> v3 auth sha <auth-pass> priv aes 256 <priv-pass> Remove SNMP v1/v2c community strings: no snmp-server community <string>

---

### CTL.CISCO.MGMT.SNMPCOMM.001

**No Default SNMP Community Strings**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.2; nist_800_53_r5: IA-5;

Cisco IOS devices must not use default SNMP community strings. Default community strings such as "public" and "private" are universally known and are the first values attempted in any SNMP enumeration scan. A device with default community strings allows unauthenticated read or read-write access to its entire MIB, exposing configuration details, routing tables, interface statistics, and enabling configuration changes.

**Remediation:** Remove default SNMP community strings and replace with unique values or migrate to SNMP v3. Run: no snmp-server community public no snmp-server community private Verify with: show snmp community

---

### CTL.CISCO.MGMT.SSH.001

**SSH Version Must Be 2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.2; nist_800_53_r5: SC-8;

Cisco IOS devices must use SSH version 2. SSH version 1 has known cryptographic weaknesses including vulnerability to man-in-the-middle attacks and session hijacking. SSH v1 uses CRC-32 for integrity checking which is not cryptographically secure. An attacker on the network path can exploit these weaknesses to intercept or modify management sessions.

**Remediation:** Configure SSH version 2 explicitly. Run: ip ssh version 2 Verify with: show ip ssh

---

### CTL.CISCO.MGMT.TELNET.001

**Telnet Must Be Disabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: SC-8;

Telnet must be disabled on Cisco IOS devices. Telnet transmits all data including credentials in cleartext. An attacker with network access can capture management session traffic and extract authentication credentials using passive packet capture. All management access must use SSH which provides encrypted transport.

**Remediation:** Disable Telnet on all VTY lines and require SSH. Run: line vty 0 15 transport input ssh Verify with: show line vty 0 15 | include input

---

### CTL.CISCO.NTP.AUTH.001

**NTP Authentication Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.2; nist_800_53_r5: AU-8;

Cisco IOS devices must have NTP authentication enabled. Without NTP authentication, the device accepts time updates from any source claiming to be an NTP server. An attacker can inject false time data to manipulate log timestamps, cause certificate validation failures, invalidate time-based access controls, or create gaps in audit records by shifting the device clock forward or backward.

**Remediation:** Enable NTP authentication. Run: ntp authenticate ntp authentication-key 1 md5 <key> ntp trusted-key 1 Verify with: show ntp status

---

### CTL.CISCO.NTP.SERVERS.001

**NTP Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.2.1; nist_800_53_r5: AU-8;

Cisco IOS devices must have NTP configured with at least one time source. Without NTP, device clocks drift and log timestamps become unreliable. Inaccurate timestamps make incident response and forensic analysis extremely difficult because events cannot be correlated across devices. An attacker benefits from unreliable timestamps because their activity cannot be precisely timed or correlated with other network events.

**Remediation:** Configure NTP with a trusted time source. Run: ntp server <ntp-server-ip> Verify with: show ntp status

---

### CTL.CISCO.OSPF.AUTH.001

**OSPF Areas Must Use Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 3.2.1; nist_800_53_r5: SC-8;

All OSPF areas on Cisco IOS devices must be configured with authentication. Without OSPF authentication, an attacker connected to an OSPF-enabled network segment can inject false routing information by sending crafted OSPF hello and LSA packets. This enables traffic redirection through attacker-controlled hosts, black-hole attacks that drop traffic silently, and network topology manipulation that can isolate network segments.

**Remediation:** Enable OSPF authentication for all areas. Run: router ospf <process-id> area <area-id> authentication message-digest Verify with: show ip ospf | include authentication

---

### CTL.CISCO.SVC.BOOTP.001

**BOOTP Server Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: CM-7;

The BOOTP server must be disabled on Cisco IOS devices. BOOTP is a legacy protocol used to assign IP addresses and boot images to network clients. The IOS BOOTP server listens on UDP port 67 and can serve IOS images to any client that requests them. An attacker can use BOOTP to obtain a copy of the IOS image, which enables offline vulnerability analysis and credential extraction. BOOTP also enables network-based attacks by allowing the attacker to serve malicious boot images to clients.

**Remediation:** Disable the BOOTP server on the device. Run: no ip bootp server Verify with: show ip bootp server

---

### CTL.CISCO.SVC.CDP.001

**CDP Must Be Disabled Globally**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.3; nist_800_53_r5: CM-7;

Cisco Discovery Protocol must be disabled on Cisco IOS devices. CDP broadcasts device information including hostname, IOS version, platform, IP addresses, and VLAN information in cleartext to all directly connected devices. An attacker with layer 2 access can passively collect this information to map the network topology and identify vulnerable software versions without generating any traffic that would trigger detection.

**Remediation:** Disable CDP globally. Run: no cdp run Verify with: show cdp

---

### CTL.CISCO.SVC.FINGER.001

**Finger Service Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.4; nist_800_53_r5: CM-7;

Cisco IOS devices must have the finger service disabled. The finger service exposes user session information including which users are logged in, their terminal lines, idle times, and connection sources. An attacker can use this information to enumerate active management sessions, identify administrator activity patterns, and time attacks for periods of low monitoring activity.

**Remediation:** Disable the finger service. Run: no ip finger no service finger Verify with: show running-config | include finger

---

### CTL.CISCO.SVC.GRATARP.001

**Gratuitous ARP Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.6; nist_800_53_r5: SC-7;

Cisco IOS devices must have gratuitous ARP disabled. Gratuitous ARP allows a device to announce its IP-to-MAC mapping without being asked. An attacker can send forged gratuitous ARP packets to poison the ARP cache of other devices on the network segment, redirecting traffic through the attacker's machine for man-in-the-middle attacks. This enables credential interception, session hijacking, and data exfiltration on the local network segment.

**Remediation:** Disable gratuitous ARP on interfaces. Run: no ip gratuitous-arps Verify with: show running-config | include gratuitous

---

### CTL.CISCO.SVC.HTTPD.001

**HTTPS Must Be Used Instead of HTTP for Management**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 1.2.2; nist_800_53_r5: SC-8;

HTTPS must be enabled for web-based management of Cisco IOS devices. Without HTTPS, any web management traffic falls back to cleartext HTTP, exposing administrator credentials, session tokens, and configuration data to network interception. TLS encryption provided by HTTPS protects the confidentiality and integrity of management sessions. Even when the HTTP server is disabled, HTTPS should be explicitly enabled to ensure that any future web management configuration defaults to encrypted transport.

**Remediation:** Enable the HTTPS server on the device. Run: ip http secure-server Verify with: show ip http server status Ensure the HTTP server is disabled with: no ip http server

---

### CTL.CISCO.SVC.SRCROUTE.001

**IP Source Routing Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.5; nist_800_53_r5: SC-7;

Cisco IOS devices must have IP source routing disabled. Source routing allows a packet sender to specify the route the packet takes through the network, bypassing normal routing decisions. An attacker can use source routing to direct traffic through specific hosts for eavesdropping, bypass firewall rules by routing around security devices, or reach internal hosts that would otherwise be unreachable from the attacker's network position.

**Remediation:** Disable IP source routing. Run: no ip source-route Verify with: show running-config | include ip source-route

---

### CTL.CISCO.SVC.TCPSMALL.001

**TCP Small Servers Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.1; nist_800_53_r5: CM-7;

Cisco IOS devices must have TCP small servers disabled. TCP small servers include echo, chargen, discard, and daytime services that provide no operational value on network infrastructure. These services can be used for amplification attacks and denial of service. The chargen service in particular is commonly exploited for reflected DDoS attacks by spoofing the source address.

**Remediation:** Disable TCP small servers. Run: no service tcp-small-servers Verify with: show running-config | include tcp-small-servers

---

### CTL.CISCO.SVC.UDPSMALL.001

**UDP Small Servers Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 2.1.2; nist_800_53_r5: CM-7;

Cisco IOS devices must have UDP small servers disabled. UDP small servers include echo, chargen, and discard services that provide no operational value on network infrastructure. These services are particularly dangerous because UDP is connectionless and source addresses are easily spoofed, making them ideal for reflected amplification attacks that can overwhelm target networks.

**Remediation:** Disable UDP small servers. Run: no service udp-small-servers Verify with: show running-config | include udp-small-servers

---

### CTL.CISCO.URPF.001

**Unicast Reverse Path Forwarding Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_cisco_ios_17: 4.3.1; nist_800_53_r5: SC-7;

Unicast Reverse Path Forwarding must be enabled on Cisco IOS devices. Without uRPF, the device accepts packets with spoofed source IP addresses. IP spoofing enables denial-of-service amplification attacks, TCP session hijacking, and evasion of IP-based access controls. uRPF verifies that the source address of each incoming packet is reachable via the interface it arrived on, dropping packets that fail this check. This is a fundamental anti-spoofing control recommended by BCP 38 (RFC 2827).

**Remediation:** Enable uRPF on all external-facing interfaces. Run: interface <interface> ip verify unicast source reachable-via rx Use "rx" (strict mode) on interfaces with a single path, or "any" (loose mode) on interfaces with asymmetric routing. Verify with: show ip verify unicast source

---


# Control Reference — VSPHERE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.VSPHERE.ESX.ACCEPTANCE.001

**ESXi Host Must Not Use CommunitySupported Acceptance Level**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.6; nist_800_53_r5: CM-5;

ESXi hosts must not accept CommunitySupported VIBs. Community packages bypass VMware's signing and quality assurance process, allowing unsigned code to run in the hypervisor kernel. An attacker can exploit this to install persistent rootkits.

**Remediation:** Raise the acceptance level to at least PartnerSupported: esxcli software acceptance set --level=PartnerSupported

---

### CTL.VSPHERE.ESX.ACCOUNT.LOCKOUT.001

**ESXi Account Lockout Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.3; nist_800_53_r5: AC-7;

ESXi hosts must have account lockout configured. Without account lockout, an attacker can perform unlimited password guessing attempts against local ESXi accounts. The DCUI, SSH, and Host Client interfaces all accept local credentials. Brute-force attacks against the root account or service accounts become trivial when there is no lockout threshold to slow or block repeated failures.

**Remediation:** Configure account lockout on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set Security.AccountLockFailures to 5 and Security.AccountUnlockTime to 900.

---

### CTL.VSPHERE.ESX.CIM.001

**ESXi CIM (SFCBD) Service Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.1; nist_800_53_r5: CM-7;

The CIM (Small Footprint CIM Broker Daemon) service on ESXi hosts must be disabled when not required. SFCBD exposes a network-accessible management interface that has been the target of multiple CVEs. If hardware monitoring is not needed, this service increases the attack surface unnecessarily.

**Remediation:** Disable the SFCBD service if hardware CIM monitoring is not required: esxcli system wbem set --enable=false

---

### CTL.VSPHERE.ESX.COREDUMP.001

**ESXi Host Must Have Core Dump Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.7; nist_800_53_r5: SI-11;

ESXi hosts must have a core dump target configured for crash analysis. Without a configured dump target, diagnostic information is lost after a host failure, preventing root cause analysis of potential security incidents.

**Remediation:** Configure a network core dump target: esxcli system coredump network set --interface-name=vmk0 --server-ipv4=<dump-server> --server-port=6500 esxcli system coredump network set --enable=true

---

### CTL.VSPHERE.ESX.DCUI.001

**DCUI Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.4; nist_800_53_r5: AC-3;

Direct Console User Interface access must be restricted on ESXi hosts. The DCUI provides physical console access to ESXi management functions including network configuration, password resets, and troubleshooting. Unrestricted DCUI access allows anyone with physical or out-of-band console access to reconfigure the host, reset the root password, or disable security settings without authentication. In environments with IPMI or iLO remote console access, DCUI exposure extends beyond physical proximity.

**Remediation:** Restrict DCUI access on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set DCUI.Access to a specific list of authorized users. Consider disabling the DCUI service entirely if not required for operations.

---

### CTL.VSPHERE.ESX.LOCKDOWN.001

**Lockdown Mode Must Be Enabled on ESXi Hosts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.2; nist_800_53_r5: CM-7;

Lockdown mode must be enabled on ESXi hosts. When lockdown mode is disabled, the host can be managed directly via local clients and APIs, bypassing vCenter role-based access controls. Enabling lockdown mode forces all management through vCenter, ensuring centralized authentication, authorization, and audit logging.

**Remediation:** Enable lockdown mode on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Security Profile > Lockdown Mode and select Normal or Strict. Normal lockdown allows DCUI access for emergency troubleshooting; Strict lockdown disables DCUI as well.

---

### CTL.VSPHERE.ESX.MOB.001

**Managed Object Browser Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.9; nist_800_53_r5: CM-7;

The Managed Object Browser must be disabled on ESXi hosts. The MOB is a web-based interface that provides direct access to the ESXi SDK object model. An authenticated attacker can use the MOB to invoke API methods, modify virtual machine configurations, extract credentials, and manipulate host settings. The MOB bypasses the vSphere Client permission model and exposes low-level SDK operations that are not intended for production use.

**Remediation:** Disable the Managed Object Browser on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set Config.HostAgent.plugins.solo.enableMob to false. No service restart is required.

---

### CTL.VSPHERE.ESX.NTP.001

**ESXi Host Must Have NTP Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.4; nist_800_53_r5: AU-8;

ESXi hosts must have NTP configured for accurate time synchronization. Without NTP, log timestamps drift and make forensic correlation unreliable. Attackers exploit time skew to hide activity across distributed systems.

**Remediation:** Configure NTP on the ESXi host using esxcli: esxcli system ntp set --server=<ntp-server> esxcli system ntp set --enabled=true

---

### CTL.VSPHERE.ESX.PERSISTLOG.001

**ESXi Host Must Have Persistent Logging Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.8; nist_800_53_r5: AU-9;

ESXi hosts must store logs on a persistent datastore. By default logs are written to a ramdisk scratch partition and are lost on reboot. An attacker can force a reboot to erase forensic evidence.

**Remediation:** Configure a persistent log location on a VMFS datastore: esxcli system syslog config set --logdir=/vmfs/volumes/<datastore>/logs esxcli system syslog reload

---

### CTL.VSPHERE.ESX.SHELL.001

**ESXi Shell Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.2;

The ESXi shell must be disabled. An enabled shell provides local console access to the hypervisor, bypassing remote management audit controls.

**Remediation:** Disable the ESXi Shell service. Set startup policy to manual.

---

### CTL.VSPHERE.ESX.SLP.001

**ESXi SLP Service Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.2; nist_800_53_r5: CM-7;

The Service Location Protocol (SLP) service on ESXi hosts must be disabled. SLP has been exploited in critical remote code execution attacks (CVE-2021-21974) and provides no value in environments using vCenter for management. Leaving it enabled exposes a high-risk network service.

**Remediation:** Disable the SLP service: /etc/init.d/slpd stop esxcli network firewall ruleset set --ruleset-id=CIMSLP --enabled=false chkconfig slpd off

---

### CTL.VSPHERE.ESX.SNMP.001

**SNMP Must Be Disabled or Configured Securely**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.8; nist_800_53_r5: CM-7;

SNMP on ESXi hosts must be disabled or configured with SNMPv3 authentication and encryption. SNMPv1 and SNMPv2c transmit community strings in cleartext, allowing any attacker with network access to intercept credentials and query host information. SNMP write access with a known community string enables remote reconfiguration of the host. Even read-only SNMP access exposes detailed hardware, software, and network configuration data useful for reconnaissance.

**Remediation:** Disable SNMP if not required. If SNMP monitoring is needed, configure SNMPv3 with authentication and privacy. Use esxcli system snmp set --enable false to disable SNMP, or configure SNMPv3 with esxcli system snmp set --authentication SHA1 --privacy AES128.

---

### CTL.VSPHERE.ESX.SSH.001

**SSH Must Be Disabled on ESXi Hosts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.1; nist_800_53_r5: CM-7;

SSH must be disabled on ESXi hosts. An enabled SSH service exposes the ESXi management plane to remote shell access, increasing the attack surface for credential brute-force and lateral movement. ESXi management should use the vSphere Client or Host Client via HTTPS only. SSH should only be enabled temporarily for troubleshooting and disabled immediately after.

**Remediation:** Disable the SSH service on the ESXi host. In the vSphere Client, navigate to Host > Configure > System > Services, select SSH, and click Stop. Set the startup policy to "Start and stop manually" to prevent automatic re-enablement.

---

### CTL.VSPHERE.ESX.SYSLOG.001

**ESXi Host Must Have Syslog Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.5; nist_800_53_r5: AU-4;

ESXi hosts must forward logs to a remote syslog server. Without centralized logging, an attacker who compromises the host can destroy local logs and erase evidence of the intrusion.

**Remediation:** Configure remote syslog on the ESXi host using esxcli: esxcli system syslog config set --loghost=<protocol>://<host>:<port> esxcli system syslog reload

---

### CTL.VSPHERE.ESX.TLS.001

**ESXi Must Use TLS 1.2 or Higher**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 1.6; nist_800_53_r5: SC-8;

ESXi hosts must use TLS 1.2 or higher for all management connections. TLS 1.0 and 1.1 have known cryptographic weaknesses including vulnerability to BEAST, POODLE, and other protocol downgrade attacks. Management traffic to ESXi hosts carries authentication credentials, virtual machine data, and configuration changes. An attacker on the network path can exploit TLS 1.0/1.1 weaknesses to decrypt or modify this traffic.

**Remediation:** Configure the ESXi host to require TLS 1.2 or higher. In the vSphere Client, navigate to Host > Configure > System > Advanced System Settings. Set UserVars.ESXiVPsDisabledProtocols to "sslv3,tlsv1,tlsv1.1" to disable all protocols below TLS 1.2. Restart management agents after the change.

---

### CTL.VSPHERE.FIREWALL.ENABLED.001

**ESXi Host Firewall Must Be Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 3.1; nist_800_53_r5: SC-7;

The ESXi host firewall must be enabled to restrict network access to management services. With the firewall disabled, all ESXi services are reachable from any network, dramatically increasing the attack surface for remote exploitation.

**Remediation:** Enable the ESXi host firewall: esxcli network firewall set --enabled=true Review and restrict firewall rulesets to only required services.

---

### CTL.VSPHERE.ISCSI.CHAP.001

**iSCSI Storage Must Require CHAP Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 6.2; nist_800_53_r5: IA-2;

iSCSI datastores must require CHAP authentication. Without CHAP, any host on the storage network can connect to the iSCSI target and access virtual machine disk data. This enables data exfiltration and tampering from a compromised host.

**Remediation:** Configure mutual CHAP authentication on iSCSI adapters: Navigate to Host > Configure > Storage Adapters > iSCSI Adapter > Authentication > Use bidirectional CHAP.

---

### CTL.VSPHERE.NFS.AUTH.001

**NFS Storage Must Require Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 6.1; nist_800_53_r5: IA-2;

NFS datastores must require authentication (Kerberos). Unauthenticated NFS mounts rely solely on IP-based access control, which is trivially bypassed through IP spoofing or compromised hosts on the same network segment.

**Remediation:** Configure NFS datastores to use Kerberos authentication (NFS 4.1 with SEC_KRB5). Migrate from NFS 3 to NFS 4.1 if necessary to support authenticated mounts.

---

### CTL.VSPHERE.VCSA.CEIP.001

**Customer Experience Improvement Program Must Be Disabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.6; nist_800_53_r5: SC-7;

The VMware Customer Experience Improvement Program must be disabled on vCenter Server. CEIP collects configuration and usage telemetry from the vCenter environment and transmits it to VMware over the internet. This telemetry includes information about host counts, virtual machine configurations, feature usage patterns, and environment topology. In regulated environments, transmitting infrastructure metadata to an external party may violate data sovereignty or confidentiality requirements. The outbound connection also increases the attack surface.

**Remediation:** Disable CEIP in the vSphere Client. Navigate to Administration > Customer Experience Improvement Program and deselect the participation checkbox. Alternatively, use the vCenter Server Management Interface at https://<vcenter>:5480 to disable CEIP under Telemetry.

---

### CTL.VSPHERE.VCSA.PLUGINS.001

**Unauthorized vCenter Plugins Must Be Removed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.5; nist_800_53_r5: CM-7;

Unauthorized plugins must be removed from vCenter Server. vCenter plugins execute with the privileges of the vCenter service and have full access to the vSphere API. A malicious or compromised plugin can exfiltrate credentials, modify virtual machine configurations, and persist across vCenter upgrades. Third-party plugins that are no longer maintained may contain unpatched vulnerabilities that an attacker can exploit to gain code execution within the vCenter process.

**Remediation:** Review installed plugins in the vSphere Client. Navigate to Administration > Solutions > Client Plug-Ins. Remove any plugins that are not authorized, no longer maintained, or not required for operations. Verify the publisher and version of all remaining plugins.

---

### CTL.VSPHERE.VCSA.SSO.LOCKOUT.001

**vCenter SSO Account Lockout Must Be Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.1; nist_800_53_r5: AC-7;

vCenter Single Sign-On must have account lockout configured. Without lockout, an attacker can perform unlimited password guessing attempts against the SSO identity source. The vCenter SSO service authenticates all access to the vSphere management plane including the vSphere Client, API, and PowerCLI. A compromised SSO administrator account grants full control over all ESXi hosts, virtual machines, and infrastructure managed by the vCenter instance.

**Remediation:** Configure SSO account lockout in the vSphere Client. Navigate to Administration > Single Sign-On > Configuration > Accounts. Set Maximum number of failed login attempts to 5 and Time interval between failures to 180 seconds. Set Unlock time to 900 seconds.

---

### CTL.VSPHERE.VCSA.SSO.PASSLEN.001

**vCenter SSO Password Length Must Be 15+**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 2.2; nist_800_53_r5: IA-5;

vCenter SSO must enforce a minimum password length of 15 characters. Short passwords are vulnerable to brute-force and dictionary attacks. The SSO password policy applies to all accounts in the vsphere.local identity source including the administrator@vsphere.local account. A weak password on this account grants an attacker full administrative control over the entire vSphere environment. NIST SP 800-63B recommends a minimum of 15 characters for privileged accounts.

**Remediation:** Configure SSO password policy in the vSphere Client. Navigate to Administration > Single Sign-On > Configuration > Accounts. Set Minimum length to 15 characters. Existing accounts with shorter passwords will be required to change their password at next login.

---

### CTL.VSPHERE.VDS.FORGED.001

**Distributed Switch Must Not Allow Forged Transmits**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.3; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow forged transmits. When enabled, a VM can send frames with a source MAC address different from its own, enabling network spoofing and lateral movement between virtual machines.

**Remediation:** Disable forged transmits on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > Forged Transmits > Reject.

---

### CTL.VSPHERE.VDS.MACCHG.001

**Distributed Switch Must Not Allow MAC Address Changes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.2; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow MAC address changes. When enabled, a VM can change its effective MAC address and impersonate other machines on the network, enabling lateral movement and man-in-the-middle attacks.

**Remediation:** Disable MAC address changes on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > MAC Address Changes > Reject.

---

### CTL.VSPHERE.VDS.PROMISC.001

**Distributed Switch Must Not Allow Promiscuous Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 4.1; nist_800_53_r5: SC-7;

vSphere Distributed Switch port groups must not allow promiscuous mode. When enabled, a VM can observe all network traffic on the switch, enabling credential sniffing and reconnaissance across the virtual network segment.

**Remediation:** Disable promiscuous mode on the distributed port group in vCenter: Navigate to Networking > Distributed Switch > Port Group > Edit Settings > Security > Promiscuous Mode > Reject.

---

### CTL.VSPHERE.VM.COPYPASTE.001

**Copy-Paste Between VM and Host Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.3.1; nist_800_53_r5: SC-7;

Copy and paste operations between the guest VM and the host must be disabled. When enabled, the shared clipboard allows data to move between the VM and the host or client system without network controls or logging. An attacker with access to a compromised VM can exfiltrate data through the clipboard channel, bypassing network-based DLP and monitoring controls.

**Remediation:** Disable copy and paste by setting the VM advanced configuration parameters isolation.tools.copy.disable and isolation.tools.paste.disable to TRUE. Apply this via VM > Configure > Advanced Parameters in the vSphere Client.

---

### CTL.VSPHERE.VM.DISKSHRNK.001

**VM Disk Shrinking Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.5; nist_800_53_r5: SC-6;

Virtual machines must not allow disk shrinking operations. Disk shrinking can be triggered from within the guest OS and causes repeated grow-shrink cycles that lead to denial of service on the underlying datastore. An attacker inside the VM can exhaust datastore capacity.

**Remediation:** Disable disk shrinking on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set isolation.tools.diskShrink.disable to TRUE and isolation.tools.diskWiper.disable to TRUE.

---

### CTL.VSPHERE.VM.ENCRYPT.001

**VMs with Sensitive Data Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.2.1; nist_800_53_r5: SC-28;

Virtual machines containing sensitive data must have VM encryption enabled. Without encryption, VM disk files (VMDKs), snapshots, and vMotion traffic are stored and transmitted in cleartext. An attacker with access to the datastore or network can read VM contents directly. VM encryption protects data at rest on the datastore and in transit during vMotion operations.

**Remediation:** Enable VM encryption using a vSphere Trust Authority or Standard Key Provider. Configure a KMS cluster in vCenter, then apply a VM storage policy with encryption enabled. Encrypt the VM by editing its storage policy assignment. Note that VM encryption requires a compatible key management server.

---

### CTL.VSPHERE.VM.HGFS.001

**VM HGFS File Transfer Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.3.2; nist_800_53_r5: CM-7;

Virtual machines must have the Host Guest File System (HGFS) transfer capability disabled. HGFS allows file transfers between the ESXi host and the guest VM, providing a covert channel for data exfiltration that bypasses network-based monitoring.

**Remediation:** Disable HGFS on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set isolation.tools.hgfsServerSet.disable to TRUE.

---

### CTL.VSPHERE.VM.INDEP.001

**VM Must Not Use Independent Non-Persistent Disks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.6; nist_800_53_r5: AU-9;

Virtual machines must not use independent non-persistent disks. Changes to non-persistent disks are discarded on power-off or reset, which means security patches, agent updates, and forensic artifacts are lost. An attacker can reboot the VM to erase evidence of compromise.

**Remediation:** Change the disk mode to persistent or dependent: Edit VM Settings > Hard Disk > Disk Mode > Persistent. Ensure backups and snapshots capture the correct disk state.

---

### CTL.VSPHERE.VM.LOGSIZE.001

**VM Log Size Must Be Limited**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.4.4;

VM diagnostic log size must be limited to prevent a compromised VM from filling the datastore via excessive logging, causing denial of service to other VMs on the same datastore.

**Remediation:** Set log.rotateSize and log.keepOld in the VM advanced settings.

---

### CTL.VSPHERE.VM.REMOTEDISP.001

**VM Remote Display Must Be Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.1; nist_800_53_r5: CM-7;

Virtual machines must not have the remote display (VNC) feature enabled. The remote display exposes an unauthenticated VNC connection to the VM console, allowing any network-adjacent attacker to view and interact with the VM.

**Remediation:** Disable the remote display on the VM: Edit VM Settings > Advanced > Configuration Parameters > Set RemoteDisplay.vnc.enabled to FALSE.

---

### CTL.VSPHERE.VM.SNAPSHOT.AGE.001

**No VM Snapshot Older Than 30 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 8.4.1;

VM snapshots must not be older than 30 days. Stale snapshots consume datastore space, degrade VM performance due to increased I/O chain depth, and create operational risk during consolidation. Long-lived snapshots also represent a data exposure risk — they preserve the VM state at a point in time that may contain credentials or sensitive data that has since been rotated.

**Remediation:** Delete or consolidate stale snapshots. In the vSphere Client, right-click the VM > Snapshots > Manage Snapshots and delete snapshots older than 30 days. Establish a policy to review and clean up snapshots on a regular schedule.

---

### CTL.VSPHERE.VSAN.ENCRYPT.001

**vSAN Must Have Data-at-Rest Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 5.1; nist_800_53_r5: SC-28;

vSAN clusters with encryption disabled expose virtual machine data to physical media theft and unauthorized access. When vSAN is enabled but encryption is not, all VM data on the cluster is stored in cleartext on the underlying disks.

**Remediation:** Enable vSAN encryption in vCenter: Navigate to Cluster > Configure > vSAN > Services > Encryption > Enable. A KMS server must be configured before enabling encryption.

---

### CTL.VSPHERE.VSAN.TRANSIT.001

**vSAN Must Have Data-in-Transit Encryption Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_vmware_esxi_7: 5.2; nist_800_53_r5: SC-8;

vSAN clusters must encrypt data in transit between hosts. Without transit encryption, inter-host vSAN traffic traverses the network in cleartext, allowing an attacker with network access to intercept VM data and credentials.

**Remediation:** Enable vSAN data-in-transit encryption in vCenter: Navigate to Cluster > Configure > vSAN > Services > Encryption > Enable data-in-transit encryption.

---


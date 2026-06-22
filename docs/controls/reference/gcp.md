# Control Reference — GCP

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GCP.ACCESSCONTEXT.PERIMETER.001

**VPC Service Controls Perimeter Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.11; nist_800_53_r5: SC-7; soc2: CC6.6;

No VPC Service Controls perimeter configured. GCP services are accessible from any network — no exfiltration boundary restricts API access to specific VPCs, IPs, or identity attributes.

**Remediation:** Configure a VPC Service Controls perimeter.

---

### CTL.GCP.ALERT.GHOST.001

**Alerting Policy References Deleted Notification Channel**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-5; soc2: CC7.2;

Alerting policy references a deleted notification channel. The alert fires but notifications go nowhere. The system appears active but delivery is silently broken.

**Remediation:** Update the alerting policy to reference a valid notification channel.

---

### CTL.GCP.ARTIFACT.SCAN.001

**Artifact Registry Vulnerability Scanning Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Vulnerability scanning not enabled. Pushed container images are not scanned for known CVEs before deployment.

**Remediation:** Enable vulnerability scanning on the repository.

---

### CTL.GCP.BIGQUERY.ENCRYPT.001

**BigQuery Dataset Not Encrypted with CMEK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 7.2; nist_800_53_r5: SC-28; pci_dss_v4: 3.4; soc2: CC6.1;

Dataset uses Google-managed encryption. CMEK via Cloud KMS provides key revocation, custom rotation, and access audit.

**Remediation:** Configure a Cloud KMS CMEK for the dataset.

---

### CTL.GCP.BIGQUERY.LOG.001

**BigQuery Data Access Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 7.3; hipaa: 164.312(b); nist_800_53_r5: AU-2; soc2: CC7.2;

Data Access audit logs not enabled for BigQuery. Query execution, table reads, and data exports are not recorded.

**Remediation:** Enable Data Access audit logs for BigQuery.

---

### CTL.GCP.BIGQUERY.PUBLIC.001

**BigQuery Dataset Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 7.1; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4: 7.2.1; soc2: CC6.1;

Dataset IAM binding includes allUsers or allAuthenticatedUsers. Anyone can query the dataset's tables via standard SQL.

**Remediation:** Remove allUsers and allAuthenticatedUsers from dataset IAM bindings.

---

### CTL.GCP.CLOUDSQL.BACKUP.001

**Cloud SQL Automated Backups Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.7; hipaa: 164.308(a)(7); nist_800_53_r5: CP-9; soc2: A1.2;

Automated backups disabled. No recovery point exists. Data loss on instance failure is permanent.

**Remediation:** Enable automated backups.

---

### CTL.GCP.CLOUDSQL.ENCRYPT.001

**Cloud SQL Not Encrypted with CMEK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 6.6; nist_800_53_r5: SC-28; pci_dss_v4: 3.4; soc2: CC6.1;

Instance uses Google-managed encryption. CMEK via Cloud KMS provides key revocation, custom rotation, and access audit.

**Remediation:** Recreate instance with a Cloud KMS CMEK.

---

### CTL.GCP.CLOUDSQL.HA.001

**Cloud SQL High Availability Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.2;

No high availability configuration. Instance runs in a single zone. Zone failure causes database outage.

**Remediation:** Enable high availability (regional instance).

---

### CTL.GCP.CLOUDSQL.MYSQL.LOCALINFILE.001

**Cloud SQL MySQL local_infile Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.3.1; nist_800_53_r5: CM-6; pci_dss_v4: 6.2; soc2: CC6.1;

local_infile enabled. LOAD DATA LOCAL INFILE can read arbitrary files from the server filesystem. Known exploitation technique.

**Remediation:** Disable local_infile flag.

---

### CTL.GCP.CLOUDSQL.MYSQL.SHOWDB.001

**Cloud SQL MySQL skip_show_database Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.3.2; nist_800_53_r5: AC-3; soc2: CC6.1;

skip_show_database not set. Any authenticated user can enumerate all databases, providing reconnaissance information.

**Remediation:** Enable skip_show_database flag.

---

### CTL.GCP.CLOUDSQL.PG.LOG.001

**Cloud SQL PostgreSQL Logging Flags Not Fully Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.2.1; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4: 10.2; soc2: CC7.1;

One or more CIS-recommended PostgreSQL logging flags disabled. Consolidates: log_checkpoints, log_connections, log_disconnections, log_lock_waits, log_min_duration_statement, log_temp_files, pgaudit.

**Remediation:** Enable all recommended PostgreSQL logging flags.

---

### CTL.GCP.CLOUDSQL.PG.MESSAGES.001

**Cloud SQL PostgreSQL Log Level Below WARNING**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.2.6; nist_800_53_r5: AU-2; soc2: CC7.1;

log_min_messages set above WARNING. WARNING-level messages indicating emerging problems may not be captured.

**Remediation:** Set log_min_messages to WARNING or lower.

---

### CTL.GCP.CLOUDSQL.PITR.001

**Cloud SQL Point-in-Time Recovery Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.8; nist_800_53_r5: CP-9; soc2: A1.2;

PITR not enabled. Recovery limited to the last automated backup. Data changes between the last backup and failure are lost.

**Remediation:** Enable point-in-time recovery.

---

### CTL.GCP.CLOUDSQL.PRIVATE.001

**Cloud SQL Instance Not Using Private IP Only**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.2; nist_800_53_r5: AC-4; soc2: CC6.6;

Instance has a public IP assigned. Even with restricted authorized networks, the database endpoint is exposed to the internet. Private IP only ensures VPC-only reachability.

**Remediation:** Configure private IP only and remove public IP.

---

### CTL.GCP.CLOUDSQL.PUBLIC.001

**Cloud SQL Instance Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.5; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4: 1.3; soc2: CC6.6;

Instance has a public IP and/or authorized networks includes 0.0.0.0/0. Database reachable from the internet.

**Remediation:** Remove 0.0.0.0/0 from authorized networks and use private IP.

---

### CTL.GCP.CLOUDSQL.SQLSERVER.CROSSDB.001

**Cloud SQL SQL Server Cross-Database Ownership Chaining Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 6.3.7; nist_800_53_r5: AC-3; soc2: CC6.1;

cross_db_ownership_chaining enabled. Objects in one database can reference objects in another without explicit permissions — cross-database privilege escalation risk.

**Remediation:** Disable cross_db_ownership_chaining flag.

---

### CTL.GCP.CLOUDSQL.SSL.001

**Cloud SQL SSL Connections Not Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 6.4; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.7;

SSL not required. Database connections can be unencrypted — credentials and query data transmitted in plaintext.

**Remediation:** Enable SSL requirement on the Cloud SQL instance.

---

### CTL.GCP.COMPUTE.DEFAULTSA.001

**Compute Instance Using Default Service Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 4.1; nist_800_53_r5: AC-6; pci_dss_v4: 7.2.1; soc2: CC6.1;

Instance runs with the default Compute Engine service account which has Editor-level permissions by default.

**Remediation:** Create a custom SA with least-privilege roles.

---

### CTL.GCP.COMPUTE.ENCRYPT.001

**Compute Disk Not Encrypted with CMEK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 4.7; nist_800_53_r5: SC-28; pci_dss_v4: 3.4; soc2: CC6.1;

Disk uses Google-managed encryption. CMEK via Cloud KMS provides key revocation, custom rotation, and access audit.

**Remediation:** Recreate the disk with a Cloud KMS CMEK.

---

### CTL.GCP.COMPUTE.FIREWALL.ALL.001

**Firewall Rule Allows All Traffic from the Internet**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.8; hipaa: 164.312(a)(1); nist_800_53_r5: SC-7; pci_dss_v4: 1.3; soc2: CC6.6;

Firewall rule allows all protocols/ports from 0.0.0.0/0. The entire instance is exposed on every port.

**Remediation:** Remove the rule and create specific allow rules.

---

### CTL.GCP.COMPUTE.FIREWALL.RDP.001

**Firewall Rule Allows RDP from the Internet**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.7; nist_800_53_r5: SC-7; pci_dss_v4: 1.3; soc2: CC6.6;

Firewall rule allows TCP port 3389 from 0.0.0.0/0. RDP directly accessible from any IP on the internet.

**Remediation:** Restrict source ranges to specific IPs or use IAP.

---

### CTL.GCP.COMPUTE.FIREWALL.SSH.001

**Firewall Rule Allows SSH from the Internet**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.6; hipaa: 164.312(a)(1); nist_800_53_r5: SC-7; pci_dss_v4: 1.3; soc2: CC6.6;

Firewall rule allows TCP port 22 from 0.0.0.0/0. SSH directly accessible from any IP on the internet.

**Remediation:** Restrict source ranges to specific IPs or use IAP for SSH.

---

### CTL.GCP.COMPUTE.FLOWLOGS.001

**VPC Subnet Flow Logs Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.9; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4: 10.2; soc2: CC7.2;

VPC flow logs not enabled on the subnet. Network traffic to and from instances is not recorded for forensic investigation.

**Remediation:** Enable VPC flow logs on the subnet.

---

### CTL.GCP.COMPUTE.IPFORWARD.001

**IP Forwarding Enabled on Instance**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 4.6; nist_800_53_r5: CM-6; soc2: CC6.1;

IP forwarding enabled. The instance can forward packets between networks unless intentionally configured as a NAT gateway.

**Remediation:** Disable IP forwarding unless the instance is a network appliance.

---

### CTL.GCP.COMPUTE.NETWORK.DEFAULT.001

**Default VPC Network Exists**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.1; nist_800_53_r5: CM-6; soc2: CC6.1;

Default VPC network not deleted. Includes pre-configured firewall rules allowing SSH and RDP from 0.0.0.0/0.

**Remediation:** Delete the default network and create custom networks.

---

### CTL.GCP.COMPUTE.OSLOGIN.001

**OS Login Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 4.4; nist_800_53_r5: IA-2; soc2: CC6.1;

OS Login not enabled. SSH access managed via per-instance metadata keys rather than centralized IAM-based access with 2FA support.

**Remediation:** Enable OS Login at the project or instance level.

---

### CTL.GCP.COMPUTE.PRIVATE.001

**Subnet Without Private Google Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.5; nist_800_53_r5: AC-4; soc2: CC6.6;

Private Google Access not enabled. Instances with only internal IPs cannot reach Google APIs without NAT or external IP.

**Remediation:** Enable Private Google Access on the subnet.

---

### CTL.GCP.COMPUTE.PUBLIC.001

**Compute Instance Has External IP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 4.9; nist_800_53_r5: AC-4; pci_dss_v4: 1.3; soc2: CC6.6;

Instance has a public IP address. Directly reachable from the internet without IAP or VPN.

**Remediation:** Remove external IP and use IAP for SSH access.

---

### CTL.GCP.COMPUTE.SERIALPORT.001

**Serial Port Access Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 4.5; nist_800_53_r5: CM-7; soc2: CC6.1;

Interactive serial port access enabled. Provides console-level access bypassing network security controls and SSH authentication.

**Remediation:** Disable serial port access.

---

### CTL.GCP.COMPUTE.SHIELDED.001

**Shielded VM Features Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 4.8; nist_800_53_r5: SI-7; soc2: CC6.1;

One or more Shielded VM features disabled: Secure Boot, vTPM, or Integrity Monitoring. Boot-level malware persists undetected.

**Remediation:** Enable Secure Boot, vTPM, and Integrity Monitoring.

---

### CTL.GCP.COMPUTE.SSHKEYS.001

**Project-Wide SSH Keys Not Blocked**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 4.3; nist_800_53_r5: AC-6; soc2: CC6.1;

Instance does not block project-wide SSH keys. Any SSH key added at the project level grants access to this instance.

**Remediation:** Block project-wide SSH keys and use OS Login or per-instance keys.

---

### CTL.GCP.COMPUTE.SSL.001

**SSL Policy Allows TLS Below 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 3.10; nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.1;

SSL policy allows TLS 1.0 or 1.1 with known vulnerabilities (BEAST, POODLE, CRIME).

**Remediation:** Set minimum TLS version to 1.2.

---

### CTL.GCP.DATAPROC.ENCRYPT.001

**Dataproc Cluster Not Encrypted with CMEK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 7.4; nist_800_53_r5: SC-28; soc2: CC6.1;

Dataproc cluster disk encryption uses Google-managed keys. CMEK provides key revocation and access audit for data processing workloads.

**Remediation:** Configure CMEK encryption for the Dataproc cluster.

---

### CTL.GCP.DNS.ALGORITHM.001

**Cloud DNS DNSSEC Using Weak Key Algorithm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 3.4; nist_800_53_r5: SC-21; soc2: CC6.1;

DNSSEC enabled but uses RSASHA1. SHA-1 has known collision vulnerabilities. RSASHA256 or ECDSAP256SHA256 should be used.

**Remediation:** Change DNSSEC key algorithm to RSASHA256 or ECDSAP256SHA256.

---

### CTL.GCP.DNS.DNSSEC.001

**Cloud DNS DNSSEC Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 3.3; nist_800_53_r5: SC-20; pci_dss_v4: 1.3; soc2: CC6.6;

DNSSEC not enabled on public managed zone. DNS responses can be spoofed — an attacker can redirect traffic by forging responses.

**Remediation:** Enable DNSSEC with a strong key algorithm.

---

### CTL.GCP.DNS.LOG.001

**Cloud DNS Query Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 3.5; nist_800_53_r5: AU-12; soc2: CC7.2;

DNS query logging not enabled. DNS-based reconnaissance, data exfiltration via DNS tunneling, and anomalous query patterns go undetected.

**Remediation:** Enable DNS query logging on the managed zone.

---

### CTL.GCP.GCR.PUBLIC.001

**Container Registry Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 7.4; nist_800_53_r5: AC-3; soc2: CC6.1;

GCR's underlying storage bucket grants allUsers or allAuthenticatedUsers read access. All container images are publicly pullable — application code and potentially embedded secrets exposed.

**Remediation:** Remove allUsers/allAuthenticatedUsers from the GCR storage bucket IAM.

---

### CTL.GCP.GEMINI.LOG.001

**Gemini Code Assist Logging Not Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.2;

Gemini Code Assist logging not enabled. AI assistant interactions and code suggestions are not recorded for audit.

**Remediation:** Enable Gemini Code Assist logging.

---

### CTL.GCP.GKE.ABAC.001

**GKE Cluster Using Legacy ABAC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 7.3; nist_800_53_r5: AC-3; soc2: CC6.1;

Legacy Attribute-Based Access Control enabled instead of RBAC. ABAC provides coarser authorization without namespace-scoped fine-grained control.

**Remediation:** Disable legacy ABAC and use RBAC.

---

### CTL.GCP.GKE.PRIVATE.001

**GKE Cluster API Server Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 7.1; nist_800_53_r5: AC-4; pci_dss_v4: 1.3; soc2: CC6.6;

GKE API server accessible from the public internet. No private endpoint or master authorized networks configured.

**Remediation:** Enable private endpoint and master authorized networks.

---

### CTL.GCP.GKE.WORKLOAD.001

**GKE Workload Identity Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 7.2; nist_800_53_r5: AC-6; pci_dss_v4: 7.2.1; soc2: CC6.1;

Workload Identity not enabled. Pods use the node's service account via the metadata server — all pods on a node share the same GCP credentials. Compromise of any pod exposes the node SA.

**Remediation:** Enable Workload Identity for per-pod GCP credential scoping.

---

### CTL.GCP.IAM.APIKEY.APP.001

**API Key Not Restricted to Specific Applications**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.13; nist_800_53_r5: AC-6; soc2: CC6.1;

API key has no application restrictions (HTTP referrers, IP addresses, Android/iOS). Key usable from any source.

**Remediation:** Add application restrictions (IP, referrer, or platform).

---

### CTL.GCP.IAM.APIKEY.RESTRICT.001

**API Key Not Restricted to Specific APIs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.12; nist_800_53_r5: AC-6; soc2: CC6.1;

API key has no API restrictions — usable to call any GCP API. A leaked unrestricted key gives access to every enabled API in the project.

**Remediation:** Add API restrictions to the key or replace with a service account.

---

### CTL.GCP.IAM.APIKEY.ROTATION.001

**API Key Not Rotated**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.14; nist_800_53_r5: IA-5; owasp_nhi: NHI7; soc2: CC6.1;

API key older than 90 days. Unrotated keys accumulate risk.

**Remediation:** Rotate the API key or replace with a service account.

---

### CTL.GCP.IAM.GHOST.001

**IAM Binding References Deleted Member**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.16; nist_800_53_r5: AC-2; soc2: CC6.2;

IAM binding grants a role to a deleted member (deleted:serviceAccount:, deleted:user:, deleted:group:). GCP SA emails are reusable — a new SA with the same email inherits the binding's role grant.

**Remediation:** Remove the ghost IAM binding.

---

### CTL.GCP.IAM.KMS.SEPARATION.001

**KMS Encrypter and Decrypter Roles on Same Principal**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.8; nist_800_53_r5: AC-5; soc2: CC6.1;

Same principal has both cloudkms.cryptoKeyEncrypter and cloudkms.cryptoKeyDecrypter roles. Combined roles allow a single compromised identity to both encrypt (ransomware) and decrypt (exfiltration).

**Remediation:** Separate encrypter and decrypter roles across different principals.

---

### CTL.GCP.IAM.PRIMITIVE.001

**Primitive Role (Owner/Editor) Assigned at Project Level**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.1; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4: 7.2.1; soc2: CC6.1;

Owner or Editor primitive role assigned at project level. These legacy roles grant broad, non-granular permissions across almost every GCP service.

**Remediation:** Replace primitive roles with predefined or custom roles.

---

### CTL.GCP.IAM.PUBLIC.001

**IAM Binding Grants Access to allUsers or allAuthenticatedUsers**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 1.2; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4: 7.2.1; soc2: CC6.1;

Project/folder/org IAM binding grants a role to allUsers or allAuthenticatedUsers. Project-wide public access — every resource in the project is accessible.

**Remediation:** Remove allUsers and allAuthenticatedUsers from IAM bindings.

---

### CTL.GCP.IAM.SA.ADMIN.001

**Service Account Has Admin-Level Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.6; nist_800_53_r5: AC-6; soc2: CC6.1;

Service account has roles granting admin-level permissions (roles/owner, roles/editor, roles/iam.admin, or service-specific admin roles). High-value non-human target.

**Remediation:** Replace admin roles with least-privilege predefined roles.

---

### CTL.GCP.IAM.SA.DEFAULT.001

**Default Service Account Used**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.3; nist_800_53_r5: AC-6; pci_dss_v4: 7.2.1; soc2: CC6.1;

Default Compute Engine or App Engine service account in use. Default SAs have Editor-level permissions by default — far broader than any workload needs.

**Remediation:** Create a custom SA with least-privilege roles.

---

### CTL.GCP.IAM.SA.KEYS.001

**Service Account Has User-Managed Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.4; hipaa: 164.312(d); nist_800_53_r5: IA-5; pci_dss_v4: 8.2; soc2: CC6.1;

Service account has user-managed JSON key files. Long-lived, exportable credentials — the #1 source of GCP credential leaks. Workload Identity eliminates key files entirely.

**Remediation:** Delete user-managed keys and use Workload Identity instead.

---

### CTL.GCP.IAM.SA.ROTATION.001

**Service Account Key Not Rotated**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.5; nist_800_53_r5: IA-5; owasp_nhi: NHI7; soc2: CC6.1;

Service account key older than 90 days. Unrotated keys accumulate risk — a leaked key remains valid indefinitely if not rotated.

**Remediation:** Rotate the key or migrate to Workload Identity.

---

### CTL.GCP.IAM.SA.SEPARATION.001

**Service Account Admin and User Roles on Same Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.7; nist_800_53_r5: AC-5; soc2: CC6.1;

Same principal has both iam.serviceAccountAdmin and iam.serviceAccountUser roles. Can create SAs and impersonate them — effectively self-granting any permission.

**Remediation:** Separate SA Admin and SA User roles across different principals.

---

### CTL.GCP.KMS.GHOST.001

**Cloud KMS Key IAM Binding References Deleted Member**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

KMS key IAM binding grants cryptographic access (encrypt/decrypt) to a deleted member. A reclaimable SA email can decrypt all data encrypted by this key.

**Remediation:** Remove the ghost IAM binding from the KMS key.

---

### CTL.GCP.KMS.PUBLIC.001

**KMS Key Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 1.11; nist_800_53_r5: SC-12; soc2: CC6.1;

KMS key IAM binding includes allUsers or allAuthenticatedUsers. Anyone can perform cryptographic operations — encryption rendered meaningless.

**Remediation:** Remove allUsers and allAuthenticatedUsers from key IAM bindings.

---

### CTL.GCP.KMS.ROTATION.001

**KMS Key Rotation Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 1.10; nist_800_53_r5: SC-12; owasp_nhi: NHI7; soc2: CC6.1;

Cloud KMS key does not have automatic rotation configured. CIS requires rotation period of 365 days or less.

**Remediation:** Configure automatic key rotation with period <= 365 days.

---

### CTL.GCP.LOGGING.AUDIT.001

**Cloud Audit Logging Not Enabled for All Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 2.1; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4: 10.2; soc2: CC7.2;

Data Access audit logs not enabled for all services. Admin Activity logs are always on but Data Access logs (who accessed what data) must be explicitly enabled per service.

**Remediation:** Enable Data Access audit logs for all services.

---

### CTL.GCP.LOGGING.BUCKET.LOCK.001

**Log Bucket Retention Not Locked**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 2.4; nist_800_53_r5: AU-9; soc2: CC7.2;

Log bucket retention policy not locked. An attacker can reduce the retention period — the system deletes old logs automatically. Log tampering via configuration change.

**Remediation:** Lock the log bucket retention policy.

---

### CTL.GCP.LOGGING.BUCKET.RETENTION.001

**Log Bucket Retention Below 365 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 2.3; nist_800_53_r5: AU-12; pci_dss_v4: 10.7; soc2: CC7.2;

Log bucket retention period less than 365 days. Compliance frameworks require one year minimum audit log retention.

**Remediation:** Increase retention to at least 365 days.

---

### CTL.GCP.LOGGING.METRICS.CIS.001

**CIS-Required Log Metric Filters Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 2.5; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: AU-6; pci_dss_v4: 10.2; soc2: CC7.2;

One or more CIS-required log metric filters missing. Required: VPC network changes, firewall rule changes, IAM policy changes, Storage IAM changes, SQL config changes, custom role changes.

**Remediation:** Configure metric filters for all CIS-required operations.

---

### CTL.GCP.LOGGING.SINK.001

**No Log Sink Configured for Export**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 2.2; nist_800_53_r5: AU-6; soc2: CC7.2;

No log sink configured. Logs exist only in Cloud Logging with no export to Storage, BigQuery, or Pub/Sub for SIEM integration.

**Remediation:** Configure a log sink to export logs.

---

### CTL.GCP.MONITORING.ALERTS.001

**Metric Filters Without Alert Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 2.6; nist_800_53_r5: AU-6; soc2: CC7.2;

Log-based metric filters exist but have no corresponding alert policies. Metrics collected but no alerts fire on thresholds.

**Remediation:** Create alert policies for all metric filters.

---

### CTL.GCP.MONITORING.CHANNELS.001

**No Notification Channels Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_gcp_v3: 2.7; nist_800_53_r5: AU-5; soc2: CC7.3;

No notification channels configured for alert policies. Alerts fire but notifications go nowhere.

**Remediation:** Configure notification channels (email, SMS, PagerDuty, webhook).

---

### CTL.GCP.ORGPOLICY.DOMAIN.001

**Domain Restricted Sharing Not Enforced**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_gcp_v3: 1.15; nist_800_53_r5: AC-3; soc2: CC6.1;

Organization policy does not restrict IAM sharing to the organization's domain. Resources can be shared with any Google account including personal Gmail.

**Remediation:** Enable the iam.allowedPolicyMemberDomains organization policy constraint.

---

### CTL.GCP.STORAGE.ENCRYPT.001

**Cloud Storage Bucket Not Using Customer-Managed Encryption Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_gcp_v3: 5.3; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-28; pci_dss_v4: 3.4; soc2: CC6.1;

Bucket uses Google-managed encryption. CMEK via Cloud KMS provides key revocation, custom rotation, and access audit.

**Remediation:** Configure a Cloud KMS key for bucket encryption.

---

### CTL.GCP.STORAGE.GHOST.001

**Cloud Storage IAM Binding References Deleted Member**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Bucket IAM binding grants storage access to a deleted member. A reclaimable SA email inherits object read/write access.

**Remediation:** Remove the ghost IAM binding from the bucket.

---

### CTL.GCP.STORAGE.LOG.001

**Cloud Storage Bucket Access Logging Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 5.4; nist_800_53_r5: AU-12; soc2: CC7.2;

Access logging not enabled. Read and write operations on the bucket are not recorded for forensic investigation.

**Remediation:** Enable access logging and specify a log bucket.

---

### CTL.GCP.STORAGE.PUBLIC.001

**Cloud Storage Bucket Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 5.1; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4: 7.2.1; soc2: CC6.1;

Bucket IAM binding includes allUsers or allAuthenticatedUsers. allUsers requires no authentication. allAuthenticatedUsers means any Google account — not organizational users.

**Remediation:** Remove allUsers and allAuthenticatedUsers from IAM bindings.

---

### CTL.GCP.STORAGE.RETENTION.001

**Cloud Storage Bucket Without Retention Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 5.6; nist_800_53_r5: AU-9; soc2: CC6.1;

No retention policy configured. Objects can be deleted at any time. An unlocked policy can be reduced to zero — a locked policy provides true WORM protection.

**Remediation:** Configure and lock a retention policy.

---

### CTL.GCP.STORAGE.UNIFORM.001

**Cloud Storage Bucket Not Using Uniform Bucket-Level Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 5.2; nist_800_53_r5: AC-6; soc2: CC6.1;

Uniform bucket-level access not enabled. Legacy ACLs allow per-object access control that bypasses IAM policies.

**Remediation:** Enable uniform bucket-level access to disable legacy ACLs.

---

### CTL.GCP.STORAGE.VERSIONING.001

**Cloud Storage Bucket Versioning Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v3: 5.5; nist_800_53_r5: CP-9; soc2: CC7.2;

Object versioning not enabled. Overwritten or deleted objects have no previous version to recover.

**Remediation:** Enable object versioning on the bucket.

---


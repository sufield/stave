# Control Reference — AZURE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.AZURE.ACR.ADMIN.001

**Container Registry Admin User Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 9.15; nist_800_53_r5: AC-6; soc2: CC6.1;

Admin user provides a single shared credential with full push/pull access to all repositories. Not scoped, not auditable per-user, not integrated with RBAC.

**Remediation:** Disable admin user and use RBAC with Entra ID.

---

### CTL.AZURE.ACR.ANON.001

**Container Registry Anonymous Pull Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.16; nist_800_53_r5: AC-3; soc2: CC6.1;

Anonymous pull allows any unauthenticated client to pull images. Application code, configuration, and potentially embedded secrets are publicly accessible.

**Remediation:** Disable anonymous pull.

---

### CTL.AZURE.ACR.NETWORK.001

**Container Registry Public Network Access Unrestricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.17; nist_800_53_r5: SC-7; soc2: CC6.6;

Public network access enabled with default Allow action. Registry accessible from any IP without firewall rules.

**Remediation:** Set network default action to Deny and configure firewall rules or private endpoints.

---

### CTL.AZURE.ACR.SCAN.001

**Container Registry Image Scanning Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Image vulnerability scanning not enabled. Pushed images are not scanned for known CVEs before deployment.

**Remediation:** Enable Defender for Container Registries or integrate image scanning.

---

### CTL.AZURE.ACR.TRUST.001

**Container Registry Content Trust Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC7.1;

Content trust (Docker Content Trust / Notary) not enabled. Images are not signed — no verification that pushed images come from trusted publishers. Requires Premium SKU.

**Remediation:** Enable content trust (requires Premium SKU).

---

### CTL.AZURE.ACTIVITYLOG.EXPORT.001

**Activity Log Not Exported to Storage or Log Analytics**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.1.2; hipaa: 164.312(b); nist_800_53_r5: AU-6; pci_dss_v4: 10.2; soc2: CC7.2;

Activity Log data retained only in portal (90-day default). Without export, historical audit data is permanently lost.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.ACTIVITYLOG.RETENTION.001

**Activity Log Retention Below 365 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.1.3; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4: 10.7; soc2: CC7.2;

Activity Log exported but retention under 365 days. Compliance frameworks require one-year minimum audit log retention.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.AISEARCH.IDENTITY.001

**AI Search Without Managed Identity**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

No managed identity configured. The search service must use stored credentials to access data sources.

**Remediation:** Configure a managed identity for the search service.

---

### CTL.AZURE.AISEARCH.NETWORK.001

**AI Search Public Network Access Unrestricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Azure AI Search service accessible from the public internet. Search indexes may contain sensitive data extracted from documents and databases.

**Remediation:** Restrict public network access and use private endpoints.

---

### CTL.AZURE.AKS.NETWORK.001

**AKS Must Use Azure CNI Network Plugin**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

AKS clusters should use Azure CNI for VNet-native pod networking enabling NSG rules and network policies on pods.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.AKS.PRIVATE.001

**AKS API Server Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

AKS cluster API server must not be accessible from the public internet without authorized IP range restrictions.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.AKS.RBAC.001

**AKS Must Integrate with Entra ID for RBAC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

AKS clusters must integrate with Entra ID for centralized identity and Conditional Access enforcement on cluster access.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.AKS.VERSION.001

**AKS Must Run a Supported Kubernetes Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC6.1;

AKS clusters must run a Kubernetes version within the Azure-supported window. Unsupported versions receive no security patches.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.ALERT.GHOST.001

**Alert Rule Targets Deleted Action Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-5; soc2: CC7.2;

Azure Monitor alert rule references a deleted action group. The alert fires but notifications go nowhere. The system appears active — the alert exists, the condition evaluates — but delivery is silently broken.

**Remediation:** Update the alert rule to reference a valid action group.

---

### CTL.AZURE.APIM.HTTPS.001

**API Management Backend Not HTTPS-Only**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 9.20; nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.7;

APIM forwards requests to backend services over HTTP. Traffic between APIM and the backend is unencrypted even when the client-to-APIM connection uses HTTPS.

**Remediation:** Enforce HTTPS for all backend connections.

---

### CTL.AZURE.APIM.IDENTITY.001

**API Management Without Managed Identity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

No managed identity configured. APIM must use stored credentials to access backend services and Azure resources.

**Remediation:** Configure a system-assigned or user-assigned managed identity.

---

### CTL.AZURE.APIM.MANAGEMENT.001

**API Management Management API Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

Management API publicly accessible. An attacker with management credentials can modify API configurations, add data-exfiltrating policies, or redirect traffic.

**Remediation:** Restrict management API access to VNet or private endpoint.

---

### CTL.AZURE.APP.AUTH.001

**App Service Authentication Not Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.1; hipaa: 164.312(d); nist_800_53_r5: AC-3; pci_dss_v4: 7.2.1; soc2: CC6.1;

App Service has no authentication configured (EasyAuth). The application is accessible without identity verification.

**Remediation:** Enable App Service Authentication (EasyAuth) with an identity provider.

---

### CTL.AZURE.APP.CLIENTCERT.001

**App Service Client Certificates Not Required**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 9.9; nist_800_53_r5: IA-3; soc2: CC6.1;

Client certificates not enabled or not set to Required mode. No mTLS verification of connecting clients.

**Remediation:** Enable client certificates in Required mode.

---

### CTL.AZURE.APP.CORS.001

**App Service CORS Allows All Origins**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.6; nist_800_53_r5: AC-4; soc2: CC6.1;

CORS configuration allows requests from any origin (*). Cross-origin requests from any website are permitted.

**Remediation:** Replace wildcard (*) with specific trusted origins.

---

### CTL.AZURE.APP.DEBUG.001

**App Service Remote Debugging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.5; nist_800_53_r5: CM-7; soc2: CC6.1;

Remote debugging enabled in production. The debugging endpoint provides code-level access to the running application.

**Remediation:** Disable remote debugging.

---

### CTL.AZURE.APP.FTP.001

**App Service FTP Not Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 9.4; nist_800_53_r5: SC-8; soc2: CC6.1;

Unencrypted FTP permitted (state AllAllowed). Deployment credentials and packages transmitted in plaintext.

**Remediation:** Set FTP state to Disabled or FtpsOnly.

---

### CTL.AZURE.APP.HTTPS.001

**App Service Does Not Enforce HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 9.2; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4: 4.2.1; soc2: CC6.1;

App Service accepts HTTP connections. Traffic between clients and the application is not encrypted.

**Remediation:** Enable HTTPS Only in App Service configuration.

---

### CTL.AZURE.APP.IDENTITY.001

**App Service Without Managed Identity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 9.10; nist_800_53_r5: IA-5; soc2: CC6.1;

No managed identity configured. The application uses stored credentials instead of automatic credential rotation.

**Remediation:** Configure a system-assigned or user-assigned managed identity.

---

### CTL.AZURE.APP.INSIGHTS.001

**App Service Without Application Insights**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.2;

Application Insights not configured. No application performance monitoring, request tracing, or dependency tracking.

**Remediation:** Configure Application Insights.

---

### CTL.AZURE.APP.LOG.001

**App Service Diagnostic Logging Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.11; nist_800_53_r5: AU-2; soc2: CC7.2;

Diagnostic logging not enabled. Application errors, request logs, and platform events are not captured for investigation.

**Remediation:** Enable diagnostic logging.

---

### CTL.AZURE.APP.NETWORK.001

**App Service Public Network Access Without Restrictions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.7; nist_800_53_r5: AC-4; soc2: CC6.6;

Public network access enabled with no IP restrictions or VNet integration. The application accepts connections from any IP.

**Remediation:** Configure IP restrictions, VNet integration, or private endpoints.

---

### CTL.AZURE.APP.PRIVATE.001

**App Service Without Private Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.8; nist_800_53_r5: AC-4; soc2: CC6.6;

No private endpoint configured. Traffic between the VNet and the application traverses the public internet.

**Remediation:** Configure a private endpoint for the App Service.

---

### CTL.AZURE.APP.RUNTIME.001

**App Service Running Deprecated Runtime Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 9.12; nist_800_53_r5: SI-2; soc2: CC7.1;

App Service runs a deprecated runtime version that receives no security patches.

**Remediation:** Upgrade to a supported runtime version.

---

### CTL.AZURE.APP.TLS.001

**App Service TLS Minimum Version Below 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 9.3; nist_800_53_r5: SC-8; pci_dss_v4: 4.2.1; soc2: CC6.1;

App Service accepts TLS 1.0 or 1.1 connections with known vulnerabilities (BEAST, POODLE, CRIME).

**Remediation:** Set minimum TLS version to 1.2.

---

### CTL.AZURE.APP.VNET.001

**App Service Not Integrated with VNet**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

App Service not integrated with a VNet. Cannot access VNet resources over private connections.

**Remediation:** Configure VNet integration.

---

### CTL.AZURE.APPINSIGHTS.CONFIGURED.001

**Application Insights Not Configured for Web App**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6; soc2: CC7.2;

Application Insights not configured. No application performance monitoring, request tracing, or dependency failure detection.

**Remediation:** Configure Application Insights for the web application.

---

### CTL.AZURE.COSMOS.ENCRYPT.001

**Cosmos DB Must Use Customer-Managed Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

Cosmos DB uses service-managed encryption without Key Vault integration.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.COSMOS.NETWORK.001

**Cosmos DB Must Not Allow Public Network Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Cosmos DB accepts public internet connections without restrictions.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.DATABRICKS.NOIP.001

**Databricks Clusters Without No-Public-IP**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Cluster nodes have public IP addresses. Nodes are directly addressable from the internet. No-public-IP mode restricts nodes to private IPs only.

**Remediation:** Enable no-public-IP mode for Databricks clusters.

---

### CTL.AZURE.DATABRICKS.PUBLIC.001

**Databricks Workspace Public Network Access Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

Public network access allows connections from any IP. Notebook UI, REST API, and cluster management are internet-accessible.

**Remediation:** Disable public network access.

---

### CTL.AZURE.DATABRICKS.VNET.001

**Databricks Workspace Not VNet Injected**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Workspace not deployed into a customer VNet. No control over network security groups, route tables, or private endpoints for the workspace's compute.

**Remediation:** Deploy the workspace into a customer VNet.

---

### CTL.AZURE.DDOS.001

**VNet Must Have DDoS Protection Standard Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-5; soc2: A1.1;

Azure VNets must have DDoS Protection Standard enabled. Basic protection provides limited mitigation for volumetric attacks only.

**Remediation:** Enable DDoS Protection Standard on the VNet.

---

### CTL.AZURE.DEFENDER.ARM.001

**Defender for ARM Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.7; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender for Azure Resource Manager not enabled. No detection of anomalous ARM operations (mass deletions, suspicious deployments, lateral movement).

**Remediation:** Enable Defender for ARM at Standard tier.

---

### CTL.AZURE.DEFENDER.AUTOPROVISIONING.001

**Defender Auto-Provisioning Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.15; nist_800_53_r5: SI-4; soc2: CC7.1;

Auto-provisioning disabled. New VMs and resources are not automatically enrolled in Defender monitoring.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.DEFENDER.CONTACT.001

**Defender Security Contact Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.19; nist_800_53_r5: AU-6; soc2: CC7.3;

No email contact for Defender alerts. Security alerts generated but not delivered to the security team.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.DEFENDER.CONTAINERS.001

**Defender for Containers Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.5; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender for Containers not enabled. No container image vulnerability scanning, no runtime threat detection for AKS.

**Remediation:** Enable Defender for Containers at Standard tier.

---

### CTL.AZURE.DEFENDER.ENABLED.001

**Microsoft Defender for Cloud Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.1; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: SI-4; pci_dss_v4: 10.1; soc2: CC7.1;

Defender not enabled or on Free tier. No threat detection or advanced security capabilities active for this resource type.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.DEFENDER.EXPORT.001

**Defender Continuous Export Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.20; nist_800_53_r5: AU-6; soc2: CC7.2;

Defender findings not exported to Log Analytics or Event Hub. Findings exist only in the portal with no SIEM integration or automated response capability.

**Remediation:** Configure continuous export to Log Analytics or Event Hub.

---

### CTL.AZURE.DEFENDER.KEYVAULT.001

**Defender for Key Vault Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.6; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender for Key Vault not enabled. No detection of anomalous key access patterns, unusual secret retrieval, or suspicious management operations.

**Remediation:** Enable Defender for Key Vault at Standard tier.

---

### CTL.AZURE.DEFENDER.SERVERS.001

**Defender for Servers Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.2; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender Standard for Servers not enabled. No vulnerability assessment, file integrity monitoring, or adaptive application controls on VMs.

**Remediation:** Enable Defender for Servers at Standard tier.

---

### CTL.AZURE.DEFENDER.SQL.001

**Defender for SQL Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.3; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender for SQL Servers not enabled. No SQL threat detection for injection attempts, anomalous access, or brute force.

**Remediation:** Enable Defender for SQL Servers at Standard tier.

---

### CTL.AZURE.DEFENDER.STORAGE.001

**Defender for Storage Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 2.1.4; nist_800_53_r5: SI-4; soc2: CC7.1;

Defender for Storage not enabled. No malware scanning for uploaded blobs, no anomalous access detection.

**Remediation:** Enable Defender for Storage at Standard tier.

---

### CTL.AZURE.DEFENDER.SUPPRESSION.001

**Defender Alert Suppression Rules Overly Broad**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.2;

Alert suppression rules silence security alerts. Findings are generated but suppressed before reaching the security team.

**Remediation:** Review and narrow suppression rules.

---

### CTL.AZURE.DIAGNOSTIC.001

**Diagnostic Settings Not Configured on Key Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.1.5; nist_800_53_r5: AU-2; pci_dss_v4: 10.3; soc2: CC7.2;

Critical resource types lack diagnostic settings. Resource-level logs and metrics are not captured for investigation or alerting.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.ENTRA.APPREG.001

**Entra ID App Registrations Not Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.11; nist_800_53_r5: AC-6; soc2: CC6.1;

Any user can register applications in Entra ID. App registrations create service principals with credentials outside the normal provisioning process.

**Remediation:** Restrict app registrations to administrators.

---

### CTL.AZURE.ENTRA.PASSWORDBAN.001

**Entra ID Custom Banned Password List Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.7; nist_800_53_r5: IA-5; soc2: CC6.1;

No custom banned password list. Users can set passwords containing company name, product names, or common organizational terms.

**Remediation:** Configure a custom banned password list in Entra ID.

---

### CTL.AZURE.ENTRA.SIGNINRISK.001

**Entra ID Sign-In Risk Policy Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.2.6; nist_800_53_r5: AC-7; soc2: CC6.1;

No sign-in risk policy. Risky sign-ins (impossible travel, anonymous IP, malware-linked IP) are not blocked or challenged with MFA. Requires Entra ID P2 license.

**Remediation:** Configure a sign-in risk policy in Entra ID Identity Protection.

---

### CTL.AZURE.ENTRA.SSPR.001

**Self-Service Password Reset Not Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.6; nist_800_53_r5: IA-5; soc2: CC6.1;

Self-service password reset not enabled. Users must contact IT, leading to insecure workarounds.

**Remediation:** Enable self-service password reset for all users.

---

### CTL.AZURE.ENTRA.USERRISK.001

**Entra ID User Risk Policy Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.2.7; nist_800_53_r5: AC-7; soc2: CC6.1;

No user risk policy. Users flagged as compromised (leaked credentials, anomalous behavior) are not forced to change password or blocked. Requires Entra ID P2 license.

**Remediation:** Configure a user risk policy in Entra ID Identity Protection.

---

### CTL.AZURE.FIREWALL.LOG.001

**Azure Firewall Must Have Diagnostic Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Azure Firewall must have diagnostic logging enabled. Without logging, inspected traffic produces no audit trail.

**Remediation:** Enable diagnostic settings for AzureFirewallApplicationRule and AzureFirewallNetworkRule logs.

---

### CTL.AZURE.FIREWALL.POLICY.001

**Azure Firewall Must Have Policy with Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Azure Firewall must have a firewall policy attached with configured rules. A firewall without a policy or with an empty policy sits in the network path but inspects nothing.

**Remediation:** Attach a firewall policy with network and application rules.

---

### CTL.AZURE.FUNCTION.AUTH.001

**Azure Function App Must Have Authentication Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Azure Function apps must have authentication (App Service Auth) enabled. Without authentication, the function is publicly invocable without credentials — the Azure equivalent of AWS Lambda function URLs with AuthType NONE.

**Remediation:** Enable App Service Authentication (EasyAuth) with an identity provider.

---

### CTL.AZURE.FUNCTION.RUNTIME.001

**Azure Function App Must Not Run Deprecated Runtime**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Azure Function apps must run a supported runtime version. Deprecated runtimes receive no security patches.

**Remediation:** Upgrade to a supported runtime version.

---

### CTL.AZURE.IDENTITY.BREAKGLASS.001

**Break-Glass Account Must Be Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

At least one break-glass (emergency access) account must exist with Global Administrator role, excluded from Conditional Access policies, and monitored for usage. Without a break-glass account, a Conditional Access misconfiguration or MFA outage can lock out all administrators.

**Remediation:** Create a break-glass account per Microsoft guidance.

---

### CTL.AZURE.IDENTITY.CONDITIONAL.001

**Privileged Roles Must Have Conditional Access Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

All privileged Entra ID roles must be covered by a Conditional Access policy enforcing MFA, compliant device, and trusted location requirements. Without Conditional Access, privileged authentication has no context-based restrictions.

**Remediation:** Create a Conditional Access policy targeting privileged directory roles.

---

### CTL.AZURE.IDENTITY.GUEST.001

**Guest Users Must Not Have Privileged Role Assignments**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

External guest users in Entra ID must not be assigned privileged roles (Owner, Contributor, User Access Administrator). Guest accounts are managed outside the organization's directory.

**Remediation:** Remove privileged roles from guest accounts. Use scoped Reader or custom roles.

---

### CTL.AZURE.IDENTITY.MANAGED.001

**User-Assigned Managed Identity Must Not Be Shared Across Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

User-assigned managed identities shared across multiple services expand blast radius. A compromise of any service grants the identity's permissions to the attacker across all services sharing it.

**Remediation:** Create dedicated managed identities per service with scoped permissions.

---

### CTL.AZURE.IDENTITY.MFA.001

**MFA Must Be Enforced for Privileged Users**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.4.1; soc2: CC6.1;

All users with privileged Entra ID roles (Global Administrator, Security Administrator, Privileged Role Administrator) must have MFA enforced. Without MFA, credential stuffing or phishing compromises the most powerful accounts.

**Remediation:** Enable MFA via Conditional Access policy or per-user MFA settings.

---

### CTL.AZURE.IDENTITY.PIM.001

**Admin Roles Must Use Privileged Identity Management**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

Privileged Entra ID roles must use PIM for just-in-time activation rather than permanent assignment. Permanent admin assignments create always-active high-privilege accounts.

**Remediation:** Convert permanent assignments to PIM eligible assignments.

---

### CTL.AZURE.IDENTITY.SP.EXPIRY.001

**Service Principal Credentials Must Not Be Near Expiry**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI7; soc2: CC6.1;

Service principal credentials (certificates or secrets) must not be approaching expiration. Expired credentials cause authentication failures for automated services.

**Remediation:** Rotate the credential before expiration.

---

### CTL.AZURE.IDENTITY.SP.SECRET.001

**Service Principals Must Use Certificate Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Service principals must use certificate-based credentials instead of client secrets. Client secrets are long-lived strings that can be leaked in logs, config files, or source code.

**Remediation:** Replace client secret with certificate credential from Key Vault.

---

### CTL.AZURE.IDENTITY.STALE.001

**Inactive Users Must Not Have Active Role Assignments**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI1; soc2: CC6.1;

Users inactive for over 90 days must not retain active RBAC role assignments. Dormant accounts with active permissions are exploitation targets — the account owner isn't monitoring activity.

**Remediation:** Remove role assignments from inactive accounts or disable the accounts.

---

### CTL.AZURE.KEYVAULT.GHOST.001

**Key Vault Access Policy References Deleted Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 8.5; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; soc2: CC6.1;

Key Vault access policy grants key, secret, or certificate permissions to a principal that no longer exists in Entra ID.

**Remediation:** Remove the orphaned access policy.

---

### CTL.AZURE.KEYVAULT.KEY.EXPIRY.001

**Key Vault Keys Without Expiration Date**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 8.1; nist_800_53_r5: SC-12; owasp_nhi: NHI7; soc2: CC6.1;

Keys without expiration dates persist indefinitely. No forced rotation — a compromised key remains valid forever.

**Remediation:** Set expiration dates on all keys.

---

### CTL.AZURE.KEYVAULT.KEYSIZE.001

**Key Vault RSA Key Below Minimum Size**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 8.7; nist_800_53_r5: SC-12; soc2: CC6.1;

RSA key size below 2048 bits. Keys below this threshold are considered cryptographically weak by current standards.

**Remediation:** Generate new keys with RSA 2048 or higher.

---

### CTL.AZURE.KEYVAULT.NETWORK.001

**Key Vault Must Not Be Accessible from Public Network**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

Azure Key Vault network default action must be Deny. Key Vault stores encryption keys, secrets, and certificates — the trust anchor for all Azure encryption. Public access exposes the key store to any internet host.

**Remediation:** Set network default action to Deny and configure VNet rules or private endpoints.

---

### CTL.AZURE.KEYVAULT.PRIVATE.001

**Key Vault Without Private Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 8.6; nist_800_53_r5: AC-4; soc2: CC6.6;

No private endpoint configured. Key Vault traffic traverses the public internet.

**Remediation:** Configure a private endpoint for the Key Vault.

---

### CTL.AZURE.KEYVAULT.PURGE.001

**Key Vault Keys and Secrets Must Have Expiry Dates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Keys and secrets stored in Key Vault must have expiry dates set. Non-expiring credentials remain valid indefinitely if compromised.

**Remediation:** Set expiry dates on all keys and secrets.

---

### CTL.AZURE.KEYVAULT.RBAC.001

**Key Vault Using Access Policies Instead of RBAC**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 8.4; nist_800_53_r5: AC-3; soc2: CC6.1;

Key Vault uses vault access policies instead of Azure RBAC. Access policies are per-vault and don't integrate with Conditional Access or PIM. RBAC provides centralized, auditable, policy-enforced access control.

**Remediation:** Switch to Azure RBAC authorization model.

---

### CTL.AZURE.KEYVAULT.ROTATION.001

**Key Vault Key Rotation Policy Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 8.3; nist_800_53_r5: SC-12; owasp_nhi: NHI7; soc2: CC6.1;

No automated key rotation policy. Keys must be rotated manually — manual processes are forgotten and keys accumulate age.

**Remediation:** Configure an automated key rotation policy.

---

### CTL.AZURE.KEYVAULT.SECRET.EXPIRY.001

**Key Vault Secrets Without Expiration Date**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 8.2; nist_800_53_r5: SC-12; owasp_nhi: NHI7; soc2: CC6.1;

Secrets (passwords, API keys, connection strings) without expiration persist indefinitely without forced rotation.

**Remediation:** Set expiration dates on all secrets.

---

### CTL.AZURE.KEYVAULT.SOFTDELETE.001

**Key Vault Must Have Soft Delete and Purge Protection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.1;

Azure Key Vault must have both soft delete and purge protection enabled. Without these, deleted keys, secrets, and certificates are permanently lost with no recovery window.

**Remediation:** Enable soft delete and purge protection on the Key Vault.

---

### CTL.AZURE.LOG.ANALYTICS.001

**No Log Analytics Workspace Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.1.1; hipaa: 164.312(b); nist_800_53_r5: AU-6; pci_dss_v4: 10.3; soc2: CC7.2;

No Log Analytics workspace in the subscription. Monitoring data is fragmented with no central query or correlation capability.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.LOGANALYTICS.ACCESS.001

**Log Analytics Workspace Allows Internet Ingestion or Query**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.1.4; nist_800_53_r5: AC-4; soc2: CC6.6;

Log Analytics workspace allows data ingestion or query access from the public internet. Security logs are queryable from outside the organization's network.

**Remediation:** Disable internet ingestion and query access; use private link.

---

### CTL.AZURE.MONITOR.ALERTS.001

**No Alerts Configured for Critical Admin Operations**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 5.2.1; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: AU-6; pci_dss_v4: 10.2; soc2: CC7.2;

No Azure Monitor alert rules for critical admin operations. Role assignments, policy changes, and security resource modifications do not generate real-time alerts.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.MONITOR.ALERTS.CIS.001

**CIS-Required Activity Log Alerts Not Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_azure_v2: 5.2.1; hipaa: 164.308(a)(1)(ii)(D); nist_800_53_r5: AU-6; pci_dss_v4: 10.2; soc2: CC7.2;

One or more CIS Azure Benchmark-required Activity Log alerts are missing. Required operations: Create Policy Assignment, Create/Update/Delete NSG, Create/Update/Delete NSG Rule, Create/Update/Delete Security Solution, Create/Update/Delete SQL Server Firewall Rule.

**Remediation:** Configure Activity Log alerts for all CIS-required operations.

---

### CTL.AZURE.MYSQL.AUDIT.001

**MySQL Audit Log Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.4.4; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4: 10.2; soc2: CC7.1;

Audit logging not enabled. Database operations are not recorded for forensic investigation or compliance.

**Remediation:** Enable audit logging on the MySQL server.

---

### CTL.AZURE.MYSQL.ENCRYPT.001

**MySQL Infrastructure Encryption Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.4.6; nist_800_53_r5: SC-28; soc2: CC6.1;

Infrastructure-level double encryption not enabled. Data encrypted at the storage layer only — no second encryption layer.

**Remediation:** Enable infrastructure encryption on the MySQL server.

---

### CTL.AZURE.MYSQL.FIREWALL.001

**MySQL Firewall Allows All Azure IPs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.4.3; nist_800_53_r5: AC-4; soc2: CC6.6;

Firewall rule allows 0.0.0.0-255.255.255.255 or AllowAllAzureIps. Permits connections from ANY Azure IP globally, not just the organization's resources.

**Remediation:** Remove the allow-all rule and configure specific IP ranges.

---

### CTL.AZURE.MYSQL.PUBLIC.001

**MySQL Public Network Access Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.4.2; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4: 1.3; soc2: CC6.6;

Server accepts connections from the public internet. Database is directly reachable without VNet or private endpoint restriction.

**Remediation:** Disable public network access and use private endpoints.

---

### CTL.AZURE.MYSQL.SSL.001

**MySQL SSL Enforcement Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.4.1; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.7;

SSL enforcement disabled. Connections to the database can be unencrypted — credentials and query data transmitted in plaintext.

**Remediation:** Enable SSL enforcement on the MySQL server.

---

### CTL.AZURE.MYSQL.TLS.001

**MySQL TLS Minimum Version Below 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.4.5; nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.1;

MySQL accepts TLS 1.0 or 1.1 connections with known vulnerabilities (BEAST, POODLE, CRIME).

**Remediation:** Set minimum TLS version to 1.2.

---

### CTL.AZURE.NSG.DEFAULT.001

**NSG Must Have Custom Rules Beyond Defaults**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Azure NSGs must have custom security rules configured beyond the default rules. Default-only NSGs provide minimal network segmentation.

**Remediation:** Add custom inbound and outbound rules for your workload.

---

### CTL.AZURE.NSG.UNASSOCIATED.001

**NSG Must Be Associated with a Subnet or NIC**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-6;

Azure NSGs must be associated with at least one subnet or network interface. Unassociated NSGs contain rules that protect nothing.

**Remediation:** Associate the NSG with a subnet or delete it if unused.

---

### CTL.AZURE.NSG.UNRESTRICTED.001

**NSG Must Not Allow Unrestricted Inbound on Sensitive Ports**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Azure NSGs must not have inbound Allow rules permitting traffic from any source (0.0.0.0/0 or *) on sensitive ports (SSH 22, RDP 3389, SQL 1433/3306/5432, or all ports). NSG rules are priority-ordered — an unrestricted Allow at a low priority number overrides restrictive Deny rules with higher numbers.

**Remediation:** Restrict source addresses to specific CIDR ranges or service tags.

---

### CTL.AZURE.POLICY.COMPLIANCE.001

**Non-Compliant Azure Policy Assignments**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.4; nist_800_53_r5: AU-6; soc2: CC7.1;

Azure Policy assignments show non-compliant resources. Intended configuration state is not enforced.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.POSTGRESQL.AD.001

**PostgreSQL Entra ID Admin Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 4.3.5; nist_800_53_r5: AC-3; soc2: CC6.1;

No Entra ID administrator configured. Authentication relies solely on native PostgreSQL credentials — no centralized identity, no Conditional Access, no SSO.

**Remediation:** Configure an Entra ID administrator for the PostgreSQL server.

---

### CTL.AZURE.POSTGRESQL.ENCRYPT.001

**PostgreSQL Infrastructure Encryption Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.3.6; nist_800_53_r5: SC-28; soc2: CC6.1;

Infrastructure-level double encryption not enabled. Data encrypted at the storage layer only — no second encryption layer with a different key.

**Remediation:** Enable infrastructure encryption on the PostgreSQL server.

---

### CTL.AZURE.POSTGRESQL.FIREWALL.001

**PostgreSQL Firewall Allows All Azure IPs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.3.8; nist_800_53_r5: AC-4; soc2: CC6.6;

Firewall rule allows 0.0.0.0-255.255.255.255 or AllowAllAzureIps. Permits connections from ANY Azure IP globally, not just the organization's resources.

**Remediation:** Remove the allow-all rule and configure specific IP ranges.

---

### CTL.AZURE.POSTGRESQL.LOG.001

**PostgreSQL Server Logging Not Fully Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.3.2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4: 10.2; soc2: CC7.1;

One or more recommended logging parameters disabled: log_checkpoints, log_connections, log_disconnections, log_duration, or connection_throttling. Database activity forensics are incomplete.

**Remediation:** Enable all recommended logging parameters.

---

### CTL.AZURE.POSTGRESQL.PUBLIC.001

**PostgreSQL Public Network Access Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.3.7; hipaa: 164.312(a)(1); nist_800_53_r5: AC-4; pci_dss_v4: 1.3; soc2: CC6.6;

Server accepts connections from the public internet. Database is directly reachable without VNet or private endpoint restriction.

**Remediation:** Disable public network access and use private endpoints.

---

### CTL.AZURE.POSTGRESQL.SSL.001

**PostgreSQL SSL Enforcement Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.3.1; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.7;

SSL enforcement disabled. Connections to the database can be unencrypted — credentials and query data transmitted in plaintext.

**Remediation:** Enable SSL enforcement on the PostgreSQL server.

---

### CTL.AZURE.RBAC.CUSTOM.001

**Custom Role Definitions Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Custom Azure RBAC role definitions must not grant overly broad permissions (actions: * or dataActions: *). Custom roles should scope to specific resource types and operations.

**Remediation:** Scope actions and dataActions to specific resource providers and operations.

---

### CTL.AZURE.RBAC.GHOST.001

**RBAC Role Assignment References Deleted Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 1.21; hipaa: 164.312(a)(1); nist_800_53_r5: AC-2; soc2: CC6.2;

RBAC assignment grants permissions to a principal that no longer exists in Entra ID. The assignment persists as an "Unknown" entry.

**Remediation:** Remove the orphaned role assignment.

---

### CTL.AZURE.RBAC.OWNER.001

**Owner Role Must Not Be Broadly Assigned**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The Owner role grants full control including the ability to assign roles to others. Excessive Owner assignments at subscription or management group scope expand the blast radius of any compromised principal.

**Remediation:** Replace Owner with Contributor or custom roles scoped to specific resource groups.

---

### CTL.AZURE.RBAC.SCOPE.001

**Privileged Roles Must Not Be Assigned at Subscription Scope**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Contributor, User Access Administrator, and custom write roles should be assigned at resource group scope, not subscription scope. Subscription-scoped assignments grant permissions across all resource groups.

**Remediation:** Reassign at resource group scope with specific resource group targets.

---

### CTL.AZURE.RECOVERY.ENCRYPT.001

**Recovery Services Vault Not Using CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

Recovery Services vault uses platform-managed encryption. No revocation, no custom rotation, no access audit via Key Vault.

**Remediation:** Configure customer-managed key encryption via Key Vault.

---

### CTL.AZURE.RECOVERY.SOFTDELETE.001

**Recovery Services Vault Soft Delete Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.6; nist_800_53_r5: CP-9; soc2: CC7.2;

Soft delete not enabled for backup items. Deleted backups are permanently lost. An attacker who gains vault access can destroy all backups before a destructive attack.

**Remediation:** Enable soft delete for backup items.

---

### CTL.AZURE.SQL.ADADMIN.001

**SQL Server Entra ID Admin Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 4.1.3; nist_800_53_r5: AC-3; soc2: CC6.1;

No Entra ID administrator set. Entra ID authentication is not possible without an admin configured.

**Remediation:** Configure an Entra ID administrator for the SQL server.

---

### CTL.AZURE.SQL.ADONLY.001

**SQL Server Allows SQL Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 4.1.4; hipaa: 164.312(d); nist_800_53_r5: AC-3; soc2: CC6.1;

SQL authentication enabled alongside Entra ID. SQL credentials bypass MFA, Conditional Access, and centralized audit. Entra ID-only authentication eliminates this identity bypass.

**Remediation:** Enable Entra ID-only authentication.

---

### CTL.AZURE.SQL.AUDIT.001

**Azure SQL Auditing Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC6.1;

SQL auditing not configured. Database operations are not recorded.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.SQL.AUDIT.RETENTION.001

**SQL Auditing Retention Below 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.1.6; nist_800_53_r5: AU-12; soc2: CC7.2;

Audit logs retained fewer than 90 days. Investigation of incidents older than the retention period loses database evidence.

**Remediation:** Increase audit log retention to at least 90 days.

---

### CTL.AZURE.SQL.DEFENDER.001

**Azure SQL Must Enable Advanced Threat Protection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC6.1;

Microsoft Defender for SQL not enabled for anomaly detection.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.SQL.ENCRYPT.001

**Azure SQL TDE Must Use Customer-Managed Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

TDE uses service-managed keys without revocation or access audit.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.SQL.FIREWALL.001

**Azure SQL Must Not Allow All Azure Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Allow Azure services permits connections from ANY Azure IP globally.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.SQL.PUBLIC.001

**Azure SQL Must Not Allow Public Network Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

SQL server accepts connections from the public internet.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.SQL.TLS.001

**SQL Server TLS Minimum Version Below 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 4.1.5; nist_800_53_r5: SC-8; pci_dss_v4: 4.1; soc2: CC6.1;

SQL server accepts TLS 1.0 or 1.1 connections with known vulnerabilities (BEAST, POODLE, CRIME).

**Remediation:** Set minimum TLS version to 1.2.

---

### CTL.AZURE.SQL.VA.001

**SQL Vulnerability Assessment Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 4.2.1; nist_800_53_r5: RA-5; soc2: CC7.1;

SQL vulnerability assessment not configured. No automated scanning for misconfigurations, excessive permissions, or sensitive data exposure.

**Remediation:** Enable SQL vulnerability assessment with periodic scanning.

---

### CTL.AZURE.STORAGE.ENCRYPT.001

**Azure Storage Must Use Customer-Managed Key for Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

Azure Storage accounts must use a customer-managed key (CMK) from Azure Key Vault for encryption at rest. Microsoft-managed keys provide no revocation capability and no access audit trail.

**Remediation:** Configure customer-managed key from Azure Key Vault.

---

### CTL.AZURE.STORAGE.GHOST.001

**Storage Account Access References Deleted Identity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.2;

Storage account RBAC assignment or shared access policy references a deleted managed identity or service principal.

**Remediation:** Remove the orphaned access configuration.

---

### CTL.AZURE.STORAGE.HTTPS.001

**Azure Storage Must Require HTTPS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

Azure Storage accounts must enforce HTTPS-only access. Allowing HTTP exposes data in transit to interception.

**Remediation:** Set supportsHttpsTrafficOnly to true.

---

### CTL.AZURE.STORAGE.IMMUTABILITY.001

**Storage Container Without Immutability Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-9; soc2: CC6.1;

No immutability policy on blob containers. Objects can be modified or deleted with no WORM protection.

**Remediation:** Configure an immutability policy on the container.

---

### CTL.AZURE.STORAGE.INFRASTRUCTURE.001

**Storage Account Infrastructure Encryption Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 3.12; nist_800_53_r5: SC-28; soc2: CC6.1;

Double encryption (infrastructure + service layer) not enabled. Single layer is default — infrastructure encryption adds a second layer with a different algorithm.

**Remediation:** Enable infrastructure encryption on the storage account.

---

### CTL.AZURE.STORAGE.KEYROTATION.001

**Storage Account Key Not Rotated**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 3.2; nist_800_53_r5: IA-5; owasp_nhi: NHI7; soc2: CC6.1;

Access keys not rotated within 90 days. Long-lived keys increase the window of compromise if a key is leaked.

**Remediation:** Rotate storage account access keys.

---

### CTL.AZURE.STORAGE.LOG.001

**Azure Storage Must Have Diagnostic Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Azure Storage accounts must have diagnostic logging enabled for read, write, and delete operations. Without logging, data access patterns are invisible.

**Remediation:** Enable diagnostic logging for read, write, and delete operations.

---

### CTL.AZURE.STORAGE.NETWORK.001

**Azure Storage Must Restrict Network Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Azure Storage accounts must set the default network action to Deny, allowing access only from specified VNets and IP ranges. Default Allow exposes the storage account to all Azure and internet traffic.

**Remediation:** Set networkRuleSet.defaultAction to Deny and add VNet/IP rules.

---

### CTL.AZURE.STORAGE.PRIVATEENDPOINT.001

**Storage Account Without Private Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 3.10; nist_800_53_r5: AC-4; soc2: CC6.6;

No private endpoint configured. Traffic to storage traverses the public internet.

**Remediation:** Configure a private endpoint for the storage account.

---

### CTL.AZURE.STORAGE.PUBLIC.001

**Azure Storage Account Must Not Allow Public Blob Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Azure Storage accounts must have AllowBlobPublicAccess disabled. When enabled, individual containers can be set to public access, exposing blobs to unauthenticated internet access.

**Remediation:** Set AllowBlobPublicAccess to false on the storage account.

---

### CTL.AZURE.STORAGE.REPLICATION.001

**Cross-Tenant Replication Not Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-4; soc2: CC6.6;

Cross-tenant replication allows data to be replicated to storage accounts in other Azure tenants. Data replicated outside the organization is beyond organizational control.

**Remediation:** Disable cross-tenant replication on the storage account.

---

### CTL.AZURE.STORAGE.SHAREDKEY.001

**Storage Account Shared Key Access Not Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_azure_v2: 3.3; nist_800_53_r5: AC-3; soc2: CC6.1;

Shared key access enabled. Shared keys are long-lived bearer tokens with no identity attribution. Entra ID authorization provides identity-based access with audit logging.

**Remediation:** Disable shared key access and use Entra ID authorization.

---

### CTL.AZURE.STORAGE.SOFTDELETE.001

**Azure Storage Must Have Soft Delete Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.1;

Azure Storage accounts must enable soft delete for blobs to protect against accidental or malicious deletion. Without soft delete, deleted data is immediately and permanently lost.

**Remediation:** Enable blob soft delete with a retention period of at least 7 days.

---

### CTL.AZURE.STORAGE.TLS.001

**Azure Storage Must Enforce TLS 1.2 Minimum**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

Azure Storage accounts must set the minimum TLS version to 1.2. Older TLS versions have known vulnerabilities.

**Remediation:** Set minimumTlsVersion to TLS1_2.

---

### CTL.AZURE.VM.AUTOUPDATE.001

**VM Automatic OS Updates Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.3; nist_800_53_r5: SI-2; soc2: CC7.1;

Automatic guest OS updates not enabled. VM accumulates unpatched vulnerabilities over time.

**Remediation:** Enable automatic guest OS updates.

---

### CTL.AZURE.VM.BACKUP.001

**VM Backup Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.1; nist_800_53_r5: CP-9; soc2: CC7.2;

VM not enrolled in Azure Backup. No recovery point exists. Data loss on VM failure is permanent.

**Remediation:** Enable Azure Backup for the VM.

---

### CTL.AZURE.VM.ENCRYPT.001

**VM Disks Must Use Customer-Managed Key Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

OS and data disks must use customer-managed keys or encryption at host.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.VM.ENDPOINT.001

**VM Must Have Endpoint Protection Installed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; soc2: CC6.1;

VMs must have endpoint protection (Microsoft Defender or equivalent) for malware detection and behavioral monitoring.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.VM.EXTENSION.001

**VM Must Not Have Unauthorized Extensions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

VMs must not have extensions beyond the approved baseline. Extensions execute with system privileges and survive restarts.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.VM.MANAGEDDISK.001

**VM Using Unmanaged Disks**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.2; nist_800_53_r5: SC-28; soc2: CC6.1;

Unmanaged disks lack built-in encryption, RBAC integration, and snapshot management that managed disks provide.

**Remediation:** Migrate to managed disks.

---

### CTL.AZURE.VM.PUBLIC.001

**VM With Public IP Must Have JIT Access Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

VMs with public IPs must enable Just-In-Time access to reduce permanent exposure. Without JIT the VM is reachable 24/7.

**Remediation:** Remediate per control description.

---

### CTL.AZURE.VM.TRUSTEDLAUNCH.001

**VM Secure Boot Not Enabled (Trusted Launch)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_azure_v2: 7.5; nist_800_53_r5: SI-7; soc2: CC6.1;

Trusted Launch with Secure Boot and vTPM not enabled. No boot integrity verification — rootkits and bootkits can persist undetected across reboots.

**Remediation:** Enable Trusted Launch with Secure Boot and vTPM.

---

### CTL.AZURE.VM.UNATTACHEDDISK.001

**Unattached Disk Not Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** cis_azure_v2: 7.4; nist_800_53_r5: SC-28; soc2: CC6.1;

A disk not attached to any VM is unencrypted. Unattached disks may contain data from previous workloads — anyone with disk read access can read the data.

**Remediation:** Encrypt the disk or delete it if no longer needed.

---

### CTL.AZURE.VNET.FLOWLOG.001

**NSG Flow Logs Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

NSGs associated with VNets must have flow logs enabled for network forensics. Without flow logs, network traffic is not recorded and incident investigation has no network-level data.

**Remediation:** Enable NSG flow logs to a Storage Account or Log Analytics workspace.

---

### CTL.AZURE.VNET.PEERING.001

**VNet Peering Must Have NSG Filtering**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Peered VNets must have NSGs applied to peered subnets to filter cross-VNet traffic. Azure VNet peering allows all traffic between peered VNets by default — NSGs must be explicitly applied.

**Remediation:** Apply NSGs to subnets in both peered VNets.

---

### CTL.AZURE.WAF.MODE.001

**Application Gateway WAF Must Be in Prevention Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-3; soc2: CC6.6;

Azure Application Gateway WAF must be in Prevention mode, not Detection mode. Detection mode logs attacks without blocking them — the WAF observes attacks without stopping them.

**Remediation:** Switch WAF mode from Detection to Prevention.

---

### CTL.AZURE.WAF.POLICY.001

**Application Gateway Must Have WAF Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Azure Application Gateways must have WAF enabled. Without WAF, the gateway routes traffic to backends without application-layer inspection.

**Remediation:** Enable WAF on the Application Gateway (requires WAF_v2 SKU).

---


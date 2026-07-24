# Control Reference — GUARDDUTY

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GUARDDUTY.ECS.RUNTIME.001

**GuardDuty ECS Runtime Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty ECS Runtime Monitoring must be enabled to detect runtime threats in containers — crypto mining, malware, reverse shells, and credential access. Without runtime monitoring, container compromise proceeds undetected at the process and network level.

**Remediation:** Enable GuardDuty ECS Runtime Monitoring in the GuardDuty console or via API. Requires the GuardDuty agent deployed as a sidecar or managed add-on on ECS tasks.

---

### CTL.GUARDDUTY.EKSPROTECTION.001

**GuardDuty EKS Audit Log Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty EKS Audit Log Monitoring must be enabled to detect suspicious Kubernetes API activity — anonymous access, privilege escalation attempts, pod creation from unusual principals, and access from known malicious IPs. This is a separate feature toggle from the base GuardDuty detector and from EKS Runtime Monitoring (CTL.GUARDDUTY.ECS.RUNTIME.001). An account running EKS clusters with GuardDuty enabled but EKS Protection disabled misses Kubernetes-layer threats entirely. Part of the GuardDuty per-feature protection family discovered through cross-cloud transposition from Azure Defender for Containers.

**Remediation:** Enable EKS Protection on the GuardDuty detector: aws guardduty update-detector --detector-id <id> --features Name=EKS_AUDIT_LOGS,Status=ENABLED.

---

### CTL.GUARDDUTY.ENABLED.001

**Amazon GuardDuty Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-3; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.16; nist_800_53_r5: SI-3; nist_csf_2.0: DE.CM; pci_dss_v4.0: 5.2; soc2: CC7.1;

GuardDuty must be enabled to provide continuous threat detection. It analyzes CloudTrail, VPC Flow Logs, and DNS logs to detect reconnaissance, instance compromise, and account compromise.

**Remediation:** Enable GuardDuty: aws guardduty create-detector --enable

---

### CTL.GUARDDUTY.EXPORT.001

**GuardDuty Findings Must Be Exported to S3 for Long-Term Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** aws_security_hub: GuardDuty.3; mitre_attack: TA0005; nist_800_53_r5: AU-11;

GuardDuty retains findings for 90 days by default. Without export to S3, findings older than 90 days are permanently deleted — making it impossible to review historical threat activity during long-running investigations or compliance audits. Exporting to S3 with Object Lock provides an immutable, long-term record of all GuardDuty findings.

**Remediation:** aws guardduty create-publishing-destination --detector-id <id> --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::<bucket>,KmsKeyArn=<key-arn>

---

### CTL.GUARDDUTY.FINDING.CONSISTENCY.001

**GuardDuty Detection Method Coverage Must Be Sufficient**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty detector has fewer than 3 active detection methods. GuardDuty correlates findings across VPC Flow Logs, DNS logs, CloudTrail management events, CloudTrail data events, S3 data events, EKS audit logs, and Lambda network activity. Each disabled data source creates blind spots where threat activity goes undetected. A detector with fewer than 3 methods lacks the cross-signal correlation needed to distinguish true threats from noise.

**Remediation:** Enable additional GuardDuty data sources: S3 protection, EKS audit logs, Lambda network activity, RDS login monitoring, and runtime monitoring.

---

### CTL.GUARDDUTY.GHOST.EXPORT.S3.001

**GuardDuty Export Destination S3 Bucket Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.1; fedramp_moderate: AU-2, AU-6; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-6, AU-11, SI-4; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC7.2, CC8.1;

GuardDuty findings export is configured to deliver to an S3 bucket that has been deleted. Findings are generated but cannot be persisted beyond the 90-day retention window. Long-term threat investigation data is lost. The export configuration appears valid — the destination ARN shows the bucket name — but the bucket no longer exists. If the bucket name is re-registered under a different account, GuardDuty may resume delivery to attacker-controlled storage without any configuration change or alert.

**Remediation:** Recreate the S3 bucket with the original name and restore the KMS key policy granting GuardDuty encrypt access, or repoint the export to an existing bucket: aws guardduty update-publishing-destination --detector-id <id> --destination-id <dest-id> --destination-properties DestinationArn=arn:aws:s3:::<new-bucket>,KmsKeyArn=<key>. Enable Object Lock on the destination bucket to prevent tampering.

---

### CTL.GUARDDUTY.INCOMPLETE.001

**Complete Data Required for GuardDuty Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required GuardDuty properties.

**Remediation:** Ensure the extractor calls aws guardduty list-detectors and get-detector.

---

### CTL.GUARDDUTY.IPSET.UNRESTRICTED.001

**SCP Must Restrict GuardDuty IPSet Modification**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC6.6;

Organization SCPs must deny guardduty:CreateIPSet and guardduty:UpdateIPSet for non-approved principals. GuardDuty trusted IP lists (IPSets) suppress all findings for traffic originating from listed IPs. Pacu's guardduty__whitelist_ip module exploits this: it adds the attacker's IP to a trusted IP list, causing GuardDuty to ignore all subsequent attacker activity — port scans, credential exfiltration, API abuse — as legitimate traffic. This is a complete detection evasion technique: a single API call (CreateIPSet or UpdateIPSet) blinds the entire GuardDuty detector for that IP. Unlike disabling GuardDuty (which CTL.IAM.SCP.GUARDDUTY.001 prevents), IPSet manipulation leaves GuardDuty running and appearing healthy while silently suppressing findings. The SCP must deny both CreateIPSet (new trusted list) and UpdateIPSet (modify existing list) to prevent this bypass.

**Remediation:** Add an SCP that denies guardduty:CreateIPSet, guardduty:UpdateIPSet, and guardduty:CreateThreatIntelSet for all principals except an approved security-operations role. Audit existing IPSets for unauthorized entries.

---

### CTL.GUARDDUTY.LAMBDAPROTECTION.001

**GuardDuty Lambda Protection Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty Lambda Protection must be enabled to monitor Lambda function network activity for suspicious patterns — connections to known malicious endpoints, DNS queries to crypto-mining pools, and unusual outbound traffic. This is a separate feature toggle from the base GuardDuty detector. An account running Lambda functions with GuardDuty enabled but Lambda Protection disabled misses serverless-layer network threats. Part of the GuardDuty per-feature protection family discovered through cross-cloud transposition from Azure Defender for App Service.

**Remediation:** Enable Lambda Protection on the GuardDuty detector: aws guardduty update-detector --detector-id <id> --features Name=LAMBDA_NETWORK_LOGS,Status=ENABLED.

---

### CTL.GUARDDUTY.MALWARE.PROTECT.001

**GuardDuty Malware Protection Must Be Enabled for EC2**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** mitre_attack: TA0002; nist_800_53_r5: SI-3;

GuardDuty Malware Protection scans EBS volumes attached to EC2 instances and ECS containers when GuardDuty detects suspicious activity. It identifies crypto-mining malware, ransomware, spyware, and rootkits. Without Malware Protection, GuardDuty detects network-level and API-level threats but cannot detect malicious files already present on instance volumes.

**Remediation:** aws guardduty update-malware-scan-settings --detector-id <id> --scan-resource-criteria Include={ResourceTypes=[EC2]}

---

### CTL.GUARDDUTY.NOTIFICATION.001

**GuardDuty Findings Have No Notification Routing**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: IR-6; soc2: CC7.3;

GuardDuty is enabled and generating findings but no notification destination is configured — no SNS topic subscription, no EventBridge rule forwarding findings, no integration with an incident response platform. Findings accumulate in the GuardDuty console where no one is watching. The detector runs, detects threats, and the security team is never notified. This is the MORE failure mode: more detection without routing creates alert fatigue by design — findings exist but have no consumer.

**Remediation:** Create an EventBridge rule that matches GuardDuty finding events and routes to an SNS topic subscribed by the security team. Filter by severity (HIGH and CRITICAL at minimum) to avoid alert fatigue from informational findings.

---

### CTL.GUARDDUTY.ORG.AUTOENABLE.001

**GuardDuty Auto-Enable Not Configured for New Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SI-4; scs_c02: 4.4; soc2: CC7.1;

GuardDuty auto-enable is not configured for new member accounts joining the organization. Without auto-enable, new accounts have no threat detection until manually enrolled. An attacker who compromises a newly provisioned account operates without GuardDuty visibility during the enrollment gap.

**Remediation:** Enable auto-enable from the delegated admin: aws guardduty update-organization-configuration --detector-id <id> --auto-enable.

---

### CTL.GUARDDUTY.ORG.MEMBERS.001

**Not All Organization Members Enrolled in GuardDuty**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.1; nist_800_53_r5: SI-4, CA-7; soc2: CC7.1, CC7.2;

Not all organization member accounts are enrolled as GuardDuty members under the delegated admin detector. Accounts without GuardDuty membership are invisible to threat detection — no findings are generated for API anomalies, credential compromise, or cryptocurrency mining in those accounts. This is the same class of blind spot as missing CloudTrail or Config recorders: the attacker operates in an unmonitored account and is never detected.

**Remediation:** Enable auto-enrollment (CTL.GUARDDUTY.ORG.AUTOENABLE.001) to cover future accounts, then add existing unenrolled accounts as members via guardduty:CreateMembers. For organizations using delegated admin, the delegated admin account runs CreateMembers for each missing account.

---

### CTL.GUARDDUTY.ORG.NODELEGATED.001

**GuardDuty Has No Delegated Administrator**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6(5); scs_c02: 4.4; soc2: CC6.1;

GuardDuty is managed from the management account because no delegated administrator is registered. Day-to-day GuardDuty administration concentrates operational footprint in the management account, which holds billing, root, and the organization itself. AWS best practice is to delegate GuardDuty administration to a dedicated security account.

**Remediation:** Register a security account as delegated admin: aws guardduty enable-organization-admin-account --admin-account-id <security-acct>.

---

### CTL.GUARDDUTY.RDSPROTECTION.001

**GuardDuty RDS Protection Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty RDS Protection must be enabled to monitor RDS login activity for anomalous access patterns — brute-force login attempts, access from unusual geolocations, and logins from known malicious IPs. This is a separate feature toggle from the base GuardDuty detector. An account running RDS instances with GuardDuty enabled but RDS Protection disabled misses database-layer authentication threats. Part of the GuardDuty per-feature protection family discovered through cross-cloud transposition from Azure Defender for Databases.

**Remediation:** Enable RDS Protection on the GuardDuty detector: aws guardduty update-detector --detector-id <id> --features Name=RDS_LOGIN_EVENTS,Status=ENABLED.

---

### CTL.GUARDDUTY.REGION.COVERAGE.001

**GuardDuty Not Enabled in All Active Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.1; nist_800_53_r5: SI-4, CA-7; soc2: CC7.1, CC7.2;

GuardDuty is not enabled in all active regions for the account. GuardDuty is regional — each region runs its own detector independently. An attacker who operates in a region without an enabled detector is invisible: no API anomaly detection, no credential compromise alerts, no cryptocurrency mining findings. Unlike CloudTrail (which has an organization trail covering all regions), GuardDuty requires an enabled detector per region. Most accounts should enable GuardDuty in every region regardless of resource count — the cost is zero when no findings are generated, and the alternative is a regional blind spot.

**Remediation:** Enable a GuardDuty detector in every active region. For organizations with delegated admin, use the delegated admin account to enable detectors org-wide across all regions. Alternatively, restrict resource creation to monitored regions via SCP (deny ec2:RunInstances etc. in unmonitored regions).

---

### CTL.GUARDDUTY.RUNTIMEMONITORING.001

**GuardDuty Runtime Monitoring Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty Runtime Monitoring must be enabled to detect runtime threats across EC2, ECS, and EKS workloads — process-level events, file system access, and network connections that indicate compromise. This is the umbrella runtime feature that covers all compute types. It is distinct from CTL.GUARDDUTY.ECS.RUNTIME.001 which checks ECS-specific runtime monitoring. An account with GuardDuty enabled but Runtime Monitoring disabled misses host-level threats. Part of the GuardDuty per-feature protection family.

**Remediation:** Enable Runtime Monitoring on the GuardDuty detector: aws guardduty update-detector --detector-id <id> --features Name=RUNTIME_MONITORING,Status=ENABLED.

---

### CTL.GUARDDUTY.S3PROTECTION.001

**GuardDuty S3 Protection Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

GuardDuty S3 Protection must be enabled to monitor S3 data-plane events for suspicious access patterns — anomalous data retrieval, access from unusual geolocations, and API calls from known malicious IPs. This is a separate feature toggle from the base GuardDuty detector. An account with GuardDuty enabled but S3 Protection disabled has a false sense of coverage — the detector analyzes CloudTrail management events and VPC flow logs but ignores S3 data access entirely. This gap was discovered through cross-cloud transposition from Azure Defender for Storage, which has an explicit per-resource-type enable/disable toggle. The same pattern applies to all GuardDuty feature toggles: EKS audit, Lambda network activity, RDS login events.

**Remediation:** Enable S3 Protection on the GuardDuty detector: aws guardduty update-detector --detector-id <id> --data-sources S3Logs={Enable=true}. This adds S3 data event analysis to the existing detector without requiring additional CloudTrail configuration.

---

### CTL.GUARDDUTY.SUPPRESSION.001

**GuardDuty Must Not Have Broad Suppression Rules**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---


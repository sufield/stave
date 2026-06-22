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

### CTL.GUARDDUTY.INCOMPLETE.001

**Complete Data Required for GuardDuty Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required GuardDuty properties.

**Remediation:** Ensure the extractor calls aws guardduty list-detectors and get-detector.

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

### CTL.GUARDDUTY.SUPPRESSION.001

**GuardDuty Must Not Have Broad Suppression Rules**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---


# Control Reference — CLOUDWATCH

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CLOUDWATCH.ALARM.COMPOSITE.NOACTION.001

**Composite Alarm Has No Action Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6, 12.10; soc2: CC7.1, CC7.2, CC7.3;

CloudWatch composite alarm evaluates a rule combining multiple child alarm states but has no AlarmAction, OKAction, or InsufficientDataAction configured. The composite alarm exists for high-value correlated detection — multiple signals that together indicate a systemic problem. Without actions, the correlation is detected and discarded.

**Remediation:** Add at least one AlarmAction to the composite alarm pointing at the team's alert SNS topic: aws cloudwatch put-composite-alarm --alarm-name <name> --alarm-rule <rule> --alarm-actions <topic-arn>. Composite alarms typically warrant a higher-priority notification channel than individual child alarms (paging vs ticketing) because the correlation indicates a more severe condition than any single child.

---

### CTL.CLOUDWATCH.ALARM.DECOMMISSIONED.001

**CloudWatch Alarm Monitors Decommissioned Resource**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.9, A.8.16; nist_800_53_r5: AU-6, CM-8, IR-4, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3, CC8.1;

CloudWatch alarm monitors a metric for a resource that has been decommissioned — an EC2 instance terminated, an RDS instance deleted, a Lambda function removed. The metric stops publishing, the alarm enters INSUFFICIENT_DATA permanently, and the alarm clutters the inventory while monitoring nothing. Different from ALARM.INSUFFICIENTDATA.001 which checks the symptom (current state); this checks the root cause (the monitored resource is gone).

**Remediation:** Confirm the dimensioned resource is gone (e.g., the InstanceId is not in the EC2 inventory, the FunctionName is not in Lambda). Delete the alarm: aws cloudwatch delete-alarms --alarm-names <name>. If the resource was replaced (new InstanceId for the same logical role), update the alarm's dimensions to the new resource rather than leaving the old alarm dead.

---

### CTL.CLOUDWATCH.ALARM.DISABLED.001

**CloudWatch Alarm ActionsEnabled Is False**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 4.5; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, IR-4, IR-5, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2, CC7.3;

CloudWatch alarm has ActionsEnabled set to false. The alarm evaluates the metric and transitions states normally; the actions exist (SNS topic, Lambda function); but ActionsEnabled is false so the actions don't fire. The most invisible alarm failure — actions ARE listed, the alarm appears fully configured. ActionsEnabled is a single boolean buried in the configuration. False- protection archetype: alarm looks functional, silently muted.

**Remediation:** Re-enable actions: aws cloudwatch enable-alarm-actions --alarm-names <name>. Audit the historical reason for the disablement — common cause is a maintenance window where actions were silenced and never re-enabled. Add a follow-up alarm or process check that surfaces long-running ActionsEnabled=false states so the same lapse doesn't recur.

---

### CTL.CLOUDWATCH.ALARM.EMAILONLY.001

**Critical CloudWatch Alarm Notifies Only by Email**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: IR-4, IR-6; iso_27001_2022: A.5.24, A.5.30; nist_800_53_r5: AU-5, IR-4, IR-6, SI-4; pci_dss_v4.0: 12.10; soc2: CC7.2, CC7.3;

Critical or high-severity CloudWatch alarm references an SNS topic whose only subscribers are email addresses — no Slack/HTTPS webhook, no PagerDuty integration, no Lambda function for automation, no SQS for downstream processing. Email delivery is best-effort: delays, spam filters, full inboxes, and off-hours all degrade response time on alerts that need urgent attention.

**Remediation:** Add at least one non-email subscriber to the SNS topic: a Slack incoming-webhook HTTPS endpoint, a PagerDuty integration URL, a Lambda subscription for automation, or an SQS queue feeding an on-call rotation. Keep the email subscriber for audit trail; add the high-availability channel for response. For paging-grade alerts, prefer PagerDuty or OpsGenie HTTPS endpoints over Slack (Slack's reliability for paging is worse than its perceived UX suggests).

---

### CTL.CLOUDWATCH.ALARM.GHOST.001

**CloudWatch Alarm Actions Must Not Target Deleted SNS Topics**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-5; hipaa: 164.312(b); nist_800_53_r5: AU-5; soc2: CC7.1;

CloudWatch alarm notification actions must not reference deleted SNS topics. When the alarm fires, the notification goes nowhere. The security team is not alerted. The alarm appears configured and active in the console while notifications are silently broken.

**Remediation:** Update the alarm action to reference an existing SNS topic.

---

### CTL.CLOUDWATCH.ALARM.INSUFFICIENTDATA.001

**CloudWatch Alarm in INSUFFICIENT_DATA State for 30+ Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, SI-4, CM-3; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch alarm has been in INSUFFICIENT_DATA state for more than 30 days. INSUFFICIENT_DATA means the metric is not publishing data points — the alarm cannot evaluate because there's nothing to evaluate. Common causes: monitored resource was deleted, metric namespace or dimensions changed, CloudTrail or the metric filter's log group was deleted. The alarm exists in the console as an active alarm in a neutral state; brief INSUFFICIENT_DATA is normal during metric-publication gaps but 30+ days means the data source is permanently gone.

**Remediation:** Investigate why the metric stopped publishing. Common roots: the monitored resource was deleted, dimensions changed, the metric filter's log group is gone (see CTL.CLOUDWATCH.GHOST.METRICFILTER.LOGGROUP.001), or CloudTrail stopped logging. Either restore the data source, repoint the alarm at the new metric dimensions, or delete the dead alarm. A dead alarm in the console creates the illusion of monitoring coverage.

---

### CTL.CLOUDWATCH.ALARM.MISSINGDATA.NOTBREACHING.001

**CloudWatch Security Alarm Treats Missing Data as Not Breaching**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 4.1; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, AU-9, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2;

CloudWatch security alarm has TreatMissingData set to "notBreaching." When metric data stops arriving (resource deleted, CloudTrail stopped, application crashed), the alarm treats the absence as OK. For security alarms specifically, missing data is dangerous: an attacker who stops the data source silences the metric AND the alarm cooperates by staying OK. Operational alarms (CPU, latency) often legitimately use notBreaching when monitoring potentially-terminated resources; security alarms should use "breaching" or "missing" instead.

**Remediation:** Change TreatMissingData on the alarm: aws cloudwatch put-metric-alarm --treat-missing-data breaching (preferred for security — missing data is treated as ALARM) or --treat-missing-data missing (alarm goes to INSUFFICIENT_DATA which is observable). Pair with CTL.CLOUDWATCH.ALARM.INSUFFICIENTDATA.001 so a permanently-INSUFFICIENT_DATA security alarm surfaces.

---

### CTL.CLOUDWATCH.ALARM.NOACTION.001

**CloudWatch Alarm Has No Action Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, IR-4, IR-5, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch alarm has no actions — no AlarmAction, no OKAction, no InsufficientDataAction. The alarm evaluates the metric and transitions states normally but nobody is notified, no SNS topic receives a message, no Lambda function runs, no auto-scaling triggers. Detection without response: the alarm exists in the console showing ALARM state, but the console is not the audience.

**Remediation:** Add an AlarmAction pointing at an SNS topic that pages the relevant on-call (aws cloudwatch put-metric-alarm --alarm-actions <sns-arn>). For composite or aggregate alarms, OK and InsufficientData actions can also be useful for state-change auditing — but at minimum, every alarm needs an AlarmAction.

---

### CTL.CLOUDWATCH.ALARM.NOALARMACTION.001

**CloudWatch Alarm Has OK or InsufficientData Actions But No Alarm Action**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch alarm has OKAction or InsufficientDataAction configured but no AlarmAction. The alarm notifies when things are fine (OK) or when data is missing (INSUFFICIENT_DATA) but not when the threshold is breached (ALARM). Reversed-action misconfiguration: the team is notified when the metric recovers but not when it breaches.

**Remediation:** Add an AlarmAction: aws cloudwatch put-metric-alarm --alarm-actions <sns-arn>. The OK and InsufficientData actions remain useful for state-change auditing; the AlarmAction is the one that actually pages on-call.

---

### CTL.CLOUDWATCH.ALARM.SAMETOPIC.BLAST.001

**Multiple Critical Alarms Share One SNS Topic**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3;

More than five critical or high-severity CloudWatch alarms reference the same SNS topic for their alarm action. The topic is a single point of failure for the entire group: one topic deletion (or ghost — SNS.GHOST.ALARM) silences all of those alarms simultaneously. Blast radius scales with the number of alarms sharing the topic.

**Remediation:** Either split the alarms across multiple SNS topics by severity or by domain (one topic for security alarms, one for operational alarms, one per service team), or add a secondary backup topic to each critical alarm so notifications survive a primary topic deletion. Centralizing on one topic is acceptable for low-severity alarms; critical alarms should have at least two notification paths.

---

### CTL.CLOUDWATCH.CROSSACCOUNT.DESTINATION.OPEN.001

**CloudWatch Logs Cross-Account Destination Allows Any Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: AC-3, AU-9; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AC-4, AU-9; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.6, CC7.1;

CloudWatch Logs cross-account destination has an access policy that allows subscription filters from any AWS account. Without account restriction or aws:PrincipalOrgID, any account can stream log events to this destination, contaminating the centralized log aggregation with attacker-controlled streams that mix into the legitimate log flow.

**Remediation:** Replace the destination policy with an explicit account allow-list, or add an aws:PrincipalOrgID condition restricting sources to the organization. Apply via aws logs put-destination-policy --destination-name <name> --access-policy <json>. Audit any subscription filters already targeting the destination from accounts not currently expected — those streams may have been established while the policy was open.

---

### CTL.CLOUDWATCH.CROSSACCOUNT.NOCENTRALIZED.001

**AWS Organizations Has No Centralized CloudWatch Logging Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.4, 3.1; fedramp_moderate: AU-4, AU-9; iso_27001_2022: A.5.36, A.8.15; nist_800_53_r5: AU-4, AU-6, AU-9; pci_dss_v4.0: 10.5; soc2: CC6.1, CC7.1;

AWS Organizations is in use but CloudWatch Logs are not aggregated to a centralized logging account. Each member account stores its own logs independently. Security investigations require querying logs in each account individually; there is no single view of the organization's log data for incident response, compliance audit, or operational analysis.

**Remediation:** Designate a logging-account in the organization (typically a dedicated security/ audit account) and configure cross-account subscription filters from member accounts to a destination in that account, OR enable CloudWatch cross-account observability with the logging account as the monitoring account. SCPs can prevent member accounts from disabling the cross-account subscriptions once configured.

---

### CTL.CLOUDWATCH.CROSSACCOUNT.RETENTION.INCONSISTENT.001

**Cross-Account Log Aggregation Has Inconsistent Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(b), 164.316(b)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-11, SI-12; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC6.1, CC7.1;

CloudWatch Logs are aggregated from member accounts to a centralized logging account, but source and destination retention periods disagree. Source may retain longer than destination (logs disappear earlier in the centralized account than the source intended) or destination may retain longer than source (data minimization violated, logs persist beyond the source's policy).

**Remediation:** Decide on the canonical retention horizon for the data class (security audit, ops debug, application access) and apply it consistently to source and destination log groups: aws logs put-retention-policy --log-group-name <name> --retention-in-days <days>. Use Organizations SCPs or config-as-code to keep retention aligned automatically as new log groups are provisioned.

---

### CTL.CLOUDWATCH.GHOST.ALARM.LAMBDA.001

**CloudWatch Alarm Action References Deleted Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IR-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, IR-4, CM-2, CM-3; pci_dss_v4.0: 10.6, 12.10; soc2: CC7.1, CC7.2;

CloudWatch alarm has an action invoking a Lambda function for automated remediation. The Lambda has been deleted. The alarm fires correctly. The invocation fails. The remediation doesn't happen. Distinct from CTL.CLOUDWATCH.ALARM.GHOST.001 (alarm action targets a deleted SNS topic) — this control covers Lambda action targets, the path most often used for automated remediation rather than human notification.

**Remediation:** Either redeploy the Lambda function (same ARN) or repoint the alarm action at an active remediation function (aws cloudwatch put-metric-alarm --alarm-actions <new-lambda-arn>). If the automated remediation is no longer needed, replace with an SNS notification action so the alarm surfaces to humans instead of failing silently.

---

### CTL.CLOUDWATCH.GHOST.COMPOSITE.CHILD.001

**Composite Alarm References Deleted Child Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch composite alarm references one or more child alarms that have been deleted. The composite alarm evaluates a rule combining child alarm states (e.g., "ALARM(child1) AND ALARM(child2)"). When a child is deleted, the composite cannot evaluate the rule — it goes to INSUFFICIENT_DATA or evaluates incorrectly. Composite alarms are commonly used for high-fidelity production alerts that combine multiple signals; a ghost child silently breaks the combination.

**Remediation:** Either recreate the deleted child alarm with the same name, or update the composite alarm's AlarmRule to remove the deleted child reference. The choice depends on whether the deleted child represented an intentional simplification of the composite rule or a mistaken cleanup. Audit the composite's intended detection logic before deciding.

---

### CTL.CLOUDWATCH.GHOST.METRICFILTER.LOGGROUP.001

**CloudWatch Metric Filter References Deleted Log Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4, 4.1; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2, CC8.1;

CloudWatch metric filter is associated with a log group that has been deleted. The metric filter exists in the console — pattern, namespace, and metric name are all configured — but the log group it parses no longer exists. The filter evaluates nothing, the metric publishes no data points, and every alarm based on the metric goes to INSUFFICIENT_DATA. One deleted log group can break N metric filters, and through them N alarms — the highest multiplier ghost reference in the catalog.

**Remediation:** Either recreate the log group with the same name and recreate the metric filter on it, or repoint the metric filter at an existing log group, or delete the orphan filter if the monitoring is no longer needed. After fix, verify by triggering an event matching the filter pattern and confirming the metric publishes a data point. Audit other metric filters on the same deleted log group — they share the same fate.

---

### CTL.CLOUDWATCH.GHOST.SUBSCRIPTION.KINESIS.001

**Subscription Filter References Deleted Kinesis Stream**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-6; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2;

CloudWatch Logs subscription filter delivers log events to a Kinesis Data Stream that has been deleted. The filter matches events. The delivery fails. Matched log events are silently dropped — they don't reach the Kinesis consumer (SIEM, analytics pipeline, security data lake). For security-sensitive log groups, this is a silent ingest gap into the SIEM.

**Remediation:** Either recreate the Kinesis stream with the same ARN and reattach (aws logs put-subscription-filter --destination-arn <stream-arn>), or repoint the filter at an existing stream, or delete the subscription filter if the downstream consumer is gone for good. Audit downstream — the SIEM / analytics pipeline expecting these events has been blind for the gap window.

---

### CTL.CLOUDWATCH.GHOST.SUBSCRIPTION.LAMBDA.001

**Subscription Filter References Deleted Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-6; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2;

CloudWatch Logs subscription filter delivers log events to a Lambda function that has been deleted. Same pattern as the Kinesis ghost (separate control) but for Lambda destinations. The filter matches events. The Lambda invocation fails. Matched log events are silently dropped. Common pattern: a real-time log processing Lambda (anomaly detection, log enrichment) that gets removed without updating the subscription filter.

**Remediation:** Either redeploy the Lambda function (same ARN) or repoint the filter at an existing Lambda. If the downstream processing is no longer needed, delete the subscription filter so it doesn't accumulate drop-failures in CloudWatch Logs metrics.

---

### CTL.CLOUDWATCH.INCOMPLETE.001

**Complete Data Required for CloudWatch Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudWatch log group properties.

**Remediation:** Ensure the extractor calls aws logs describe-log-groups and maps the retentionInDays to the log_group observation properties.

---

### CTL.CLOUDWATCH.LOG.EXPORT.001

**CloudWatch Log Group Exports Must Be Restricted to Authorized Buckets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1530; nist_800_53_r5: AU-9;

CloudWatch log group export tasks copy all log data to an S3 bucket. An attacker with logs:CreateExportTask permission can export CloudTrail logs, application logs, and security tool outputs to an attacker-controlled bucket. This is particularly dangerous for CloudTrail log groups — exporting them gives the attacker a complete copy of all API activity before they cover their tracks.

**Remediation:** Restrict logs:CreateExportTask to approved S3 destinations via IAM resource conditions. Monitor for export tasks to unexpected destinations via CloudTrail alerting.

---

### CTL.CLOUDWATCH.LOG.RETENTION.001

**CloudWatch Log Groups Must Have Retention Policies Set**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** mitre_attack: T1530; nist_800_53_r5: AU-11;

CloudWatch log groups without retention policies retain logs indefinitely — creating an ever-growing collection of potentially sensitive data (application logs, access patterns, error messages containing credentials). An attacker with logs:GetLogEvents access can search through years of accumulated logs to harvest credentials, API keys, and internal system details. Retention policies limit the data collection window.

**Remediation:** Set a retention policy appropriate for the log type: aws logs put-retention-policy --log-group-name <name> --retention-in-days 90

---

### CTL.CLOUDWATCH.LOG.RETENTION365.001

**CloudWatch Log Retention Must Be At Least 365 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-11; gdpr: Art.30; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.7;

CloudWatch log groups for cardholder data environment audit logs must retain logs for at least 365 days. PCI-DSS v4.0 requires 12 months of audit trail with at least 3 months immediately available.

**Remediation:** Set retention to at least 365 days: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365

---

### CTL.CLOUDWATCH.LOGGROUP.ENCRYPT.CMK.001

**CloudWatch Log Group Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.7; fedramp_moderate: SC-13, SC-28; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-13, SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1, CC6.7;

CloudWatch Logs log group is not encrypted with a customer-managed KMS key. CW Logs encrypts data at rest by default with AWS-managed keys, but without a CMK there is no key policy control over which principals can decrypt log data, no usage audit trail in CloudTrail KMS events, and no key revocation capability. For log groups containing audit events, application logs, or security tool output, CMK encryption is the only way to bound decryption authority and revoke access.

**Remediation:** Associate a customer-managed KMS key with the log group: aws logs associate-kms-key --log-group-name <name> --kms-key-id <cmk-arn>. The key policy must grant logs.<region>.amazonaws.com kms:Encrypt, kms:Decrypt, kms:ReEncrypt*, kms:GenerateDataKey*, and kms:Describe* with a kms:EncryptionContext condition scoping to the log group ARN. After association, only entries written after association are encrypted with the CMK; existing entries remain encrypted with the previous key.

---

### CTL.CLOUDWATCH.LOGGROUP.ORPHAN.001

**CloudWatch Log Group Has No Log Streams in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-8, SI-12; soc2: CC6.1, A1.2;

CloudWatch Logs log group has not received any new log events in 90+ days. The log group exists with retention, encryption, and policy configuration — but no service writes to it. Typically indicates the writer service was deleted (Lambda function, ECS task, API Gateway), the log group was created for a service that was never deployed, or the service's log configuration was changed to a different log group. Dormant log groups continue to accrue storage cost on whatever historical data they hold.

**Remediation:** Confirm no service still depends on the log group (search Lambda function configurations, ECS task definitions, API Gateway log destinations, custom application code for the log group name). If confirmed orphaned, archive any stored data to S3 via aws logs create-export-task and delete the log group: aws logs delete-log-group --log-group-name <name>. If the data is not needed, delete directly. Stop paying storage cost on data nothing reads.

---

### CTL.CLOUDWATCH.LOGGROUP.POLICY.CROSSACCOUNT.001

**Log Group Resource Policy Grants Cross-Account Access Without Org Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: AC-3, AU-9; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AC-4, AU-9; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.6;

CloudWatch Logs log group resource policy grants logs:PutLogEvents or logs:GetLogEvents to principals in external accounts without aws:PrincipalOrgID condition. External accounts can write to or read from the log group regardless of current organizational membership.

**Remediation:** Add an aws:PrincipalOrgID condition to the resource policy restricting access to the organization. If specific external accounts legitimately need access, enumerate them as Principal and document the exception. Replace the policy via aws logs put-resource-policy --policy-name <name> --policy-document <json>.

---

### CTL.CLOUDWATCH.LOGGROUP.POLICY.PUBLIC.001

**CloudWatch Log Group Resource Policy Allows PutLogEvents from Any Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AC-3, AU-9; hipaa: 164.312(b), 164.312(c)(1); iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-9; pci_dss_v4.0: 10.5; soc2: CC6.1, CC7.1;

CloudWatch Logs log group resource policy allows logs:PutLogEvents from Principal: * or from any AWS account without an aws:PrincipalOrgID condition. Any account on the internet can write log entries — injecting fake events that mix with legitimate entries. For security log groups (the CloudTrail CW Logs target, VPC Flow Logs), injected entries contaminate the audit trail and may trigger or mask metric-filter alarms.

**Remediation:** Replace Principal: * with the specific service principal that needs to write (e.g., cloudtrail.amazonaws.com, vpc-flow-logs.amazonaws.com) and add an aws:SourceArn condition limiting writes to a specific resource. For cross-account writes, enumerate Principal accounts explicitly or add an aws:PrincipalOrgID condition. Apply the policy via aws logs put-resource-policy --policy-name <name> --policy-document <json>.

---

### CTL.CLOUDWATCH.LOGGROUP.RETENTION.SHORT.001

**CloudWatch Log Group Retention Too Short for Compliance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-11; hipaa: 164.312(b), 164.316(b)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-9, AU-11; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC7.1, A1.2;

CloudWatch Logs log group has a retention period shorter than the applicable compliance requirement. Common requirements: HIPAA 6 years (2190 days), PCI-DSS 1 year (365 days), SOC2 1 year (365 days). When the configured retention is shorter than the required minimum, security investigation data and audit evidence are deleted before the audit window closes. Compliance-profile control: fires when retention is set AND retention_compliant is false for the active compliance tag set.

**Remediation:** Update the log group retention to meet or exceed required_retention_days: aws logs put-retention-policy --log-group-name <name> --retention-in-days <days>. Allowed CW Logs retention values are discrete (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653) — pick the smallest value that meets or exceeds the required minimum.

---

### CTL.CLOUDWATCH.METRICFILTER.DECOMMISSIONED.001

**Metric Filter Monitors Decommissioned Service**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; soc2: CC8.1;

CloudWatch metric filter is on a log group whose source service has been decommissioned — the Lambda function was deleted, the ECS service was removed, the API Gateway was shut down. The log group may still exist (orphaned) or may have been recreated for a different service. The filter evaluates events from a service that no longer runs.

**Remediation:** Confirm the source service is gone and not being recreated under a different name. Delete the metric filter (aws logs delete-metric-filter --log-group-name <name> --filter-name <filter>) and any alarms that used the metric. If the log group itself is also orphaned, delete it (LOGGROUP.ORPHAN catches that separately).

---

### CTL.CLOUDWATCH.METRICFILTER.NOALARM.001

**Metric Filter Has No Alarm Watching Its Metric**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.4, 4.1; fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch metric filter exists and matches log events into a metric, but no CloudWatch alarm watches the metric. Events accumulate as metric data points; nothing reads them. The filter is detection without alerting. For security metric filters (root logins, unauthorized API calls, KMS deletions), this means the events are counted in CloudWatch metrics but never trigger a notification.

**Remediation:** Either create a CloudWatch alarm against the metric (aws cloudwatch put-metric-alarm) or delete the orphan filter (aws logs delete-metric-filter). If the metric is consumed by an external system (Datadog, CloudWatch Logs Insights queries, dashboards), document the external consumer so future audits don't re-flag it.

---

### CTL.CLOUDWATCH.METRICFILTER.NODEFAULT.001

**Metric Filter Has No Default Value**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudWatch metric filter does not have a default value configured. When no log events match the filter pattern in an evaluation period, the metric publishes NO data point — not zero, no data. Alarms based on the metric enter INSUFFICIENT_DATA instead of evaluating the threshold. Combined with TreatMissingData: notBreaching (CW-1), the alarm stays in OK state silently. Combined with TreatMissingData: missing, the alarm enters INSUFFICIENT_DATA permanently if no events ever match.

**Remediation:** Set a default value of 0 on the metric filter: aws logs put-metric-filter --metric-transformations metricName=...,metricNamespace=...,metricValue=1,defaultValue=0. This way the metric publishes 0 when no events match, the alarm has data to evaluate, and threshold logic works as expected. After update, validate the metric data shows a continuous series rather than gaps.

---

### CTL.CLOUDWATCH.MONITOR.ACCESSKEY.001

**Access Key Creation Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; nist_800_53_r5: AU-6; owasp_nhi: NHI8; soc2: CC7.2;

No CloudWatch metric filter and alarm for iam:CreateAccessKey events. Access key creation is a persistence mechanism — an attacker who creates access keys establishes long-lived credentials that survive password resets and session revocation.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching iam:CreateAccessKey events, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ANON.VPC.001

**Anonymous S3 Requests via VPC Endpoints Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must detect anonymous S3 requests transiting VPC endpoints. Even with Network Activity logging enabled, events must be actively monitored to surface anonymous access.

**Remediation:** Create a CloudWatch metric filter on Network Activity events matching anonymous (unsigned) S3 requests through VPC endpoints. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.ASSUMEROLE.001

**Cross-Account Role Assumption Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; nist_800_53_r5: SI-4; owasp_nhi: NHI8; soc2: CC7.2;

No CloudWatch metric filter and alarm for sts:AssumeRole events from external accounts. Cross-account role assumption is the entry point for lateral movement between accounts. Without an alarm, an external account assuming a role in this account goes unnoticed in real time.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching sts:AssumeRole events where the source account differs from the local account, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.AUTHFAIL.001

**Console Authentication Failures Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.6; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console authentication failures. Failed console authentication attempts indicate brute force attacks against IAM user passwords.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console authentication failures, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.BOUNDARY.001

**Permission Boundary Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; nist_800_53_r5: AU-6; owasp_nhi: NHI8; soc2: CC7.2;

No CloudWatch metric filter and alarm for iam:DeleteRolePermissionsBoundary or iam:PutRolePermissionsBoundary events. Permission boundary removal expands a role's effective permissions instantly — the boundary that constrained the role is gone, all policy permissions become effective.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching iam:DeleteRolePermissionsBoundary and iam:PutRolePermissionsBoundary events, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CMK.001

**CMK Disable or Deletion Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.7; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cmk disable or deletion. KMS key disabling or scheduled deletion renders encrypted data permanently inaccessible — a ransomware vector.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cmk disable or deletion, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CONFIG.001

**AWS Config Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.9; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws config changes. Changes to AWS Config (StopConfigurationRecorder) remove drift detection.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws config changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001

**Cross-Account AssumeRole Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor sts:AssumeRole events from external accounts. Cross-account assumption is a normal operation for partner integrations and CI/CD pipelines, but unexpected external assumptions indicate compromised trust relationships or credential theft. The metric filter should match AssumeRole events where the source account is not in the organization's known account list.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching sts:AssumeRole events where the source account differs from the target account. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.ESCALATION.001

**IAM Privilege Escalation Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; fedramp_moderate: AU-12; nist_800_53_r5: AU-12; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor IAM privilege escalation API calls. These are the specific API actions that enable an attacker to elevate permissions after initial access: CreatePolicyVersion, SetDefaultPolicyVersion, AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, UpdateAssumeRolePolicy, and PassRole (as a parameter in RunInstances, CreateFunction, CreateStack, etc.). The existing iam_policy_changes metric filter (CIS 4.4) covers general policy modifications but does not specifically surface the escalation-enabling subset. This control verifies that a dedicated escalation-focused filter and alarm exist.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching escalation-relevant API calls: { ($.eventName = CreatePolicyVersion) ||
  ($.eventName = SetDefaultPolicyVersion) ||
  ($.eventName = AttachUserPolicy) ||
  ($.eventName = AttachRolePolicy) ||
  ($.eventName = PutUserPolicy) ||
  ($.eventName = PutRolePolicy) ||
  ($.eventName = CreateAccessKey) ||
  ($.eventName = CreateLoginProfile) ||
  ($.eventName = UpdateAssumeRolePolicy) }.
Then create a CloudWatch alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.GW.001

**Network Gateway Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.12; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor network gateway changes. Gateway attachment is the boundary between a VPC and the internet.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for network gateway changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.IAMPOLICY.001

**IAM Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor iam policy changes. IAM policy modifications (CreatePolicy, DeletePolicy, AttachRolePolicy) are a primary persistence mechanism for attackers.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for iam policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.IMDS.001

**IMDS Configuration Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; owasp_nhi: NHI8; soc2: CC7.1;

CloudWatch alarms must detect changes to EC2 instance metadata options (ModifyInstanceMetadataOptions). Without monitoring, an attacker can downgrade IMDSv2 to IMDSv1 silently.

**Remediation:** Create a CloudWatch metric filter on CloudTrail events matching ModifyInstanceMetadataOptions. Create an alarm with SNS notification for any match.

---

### CTL.CLOUDWATCH.MONITOR.LAMBDA.ERRORS.001

**Lambda Error and Permission Failure Events Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudWatch alarms must be configured to detect Lambda function error spikes, throttling events, and permission failure patterns. Without monitoring, a compromised function probing IAM permissions generates AccessDenied events nobody sees, and application errors indicating exploitation accumulate without alerting.

**Remediation:** Create CloudWatch alarms for: AWS/Lambda Errors metric exceeding threshold, AWS/Lambda Throttles > 0, and CloudTrail AccessDenied/UnauthorizedAccess events filtered to Lambda- sourced principals. Configure SNS notification for each alarm.

---

### CTL.CLOUDWATCH.MONITOR.MFADEVICE.001

**MFA Device Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor MFA device enrollment and deactivation events. MFA device changes (CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, DeleteVirtualMFADevice) are a persistence mechanism — an attacker who gains temporary access can enroll their own MFA device to maintain access after the victim resets their password.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice, and DeleteVirtualMFADevice events. Create an alarm with an SNS notification action to alert on any MFA device change.

---

### CTL.CLOUDWATCH.MONITOR.NACL.001

**NACL Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.11; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor nacl changes. Network ACL changes can open or close network paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for nacl changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.NOMFA.001

**Console Sign-In Without MFA Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.2; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor console sign-in without mfa. Console sign-ins without MFA indicate either MFA is not enforced or credentials were used from a context that bypassed MFA.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for console sign-in without mfa, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ORG.001

**AWS Organizations Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.15; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor aws organizations changes. Organizations changes affect account-level governance and SCP enforcement.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for aws organizations changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.PASSROLE.001

**iam:PassRole Invocations Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; nist_800_53_r5: SI-4; owasp_nhi: NHI8; soc2: CC7.2;

No CloudWatch metric filter and alarm for iam:PassRole events. PassRole is the gateway to every compute-based privilege escalation path — EC2, Lambda, Glue, SageMaker, ECS, CodeBuild, auto-scaling. Every PassRole invocation should generate an alert because it means a principal is assigning IAM permissions to a compute resource.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching iam:PassRole events, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROOT.001

**Root Account Usage Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.3; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor root account usage. Root account API activity should be near-zero. Any activity may indicate compromise or unauthorized administrative action.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for root account usage, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.ROUTE.001

**Route Table Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.13; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor route table changes. Route table modifications can redirect traffic through attacker-controlled paths.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for route table changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.S3POLICY.001

**S3 Bucket Policy Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor s3 bucket policy changes. S3 bucket policy changes (PutBucketPolicy, PutBucketAcl) can make private buckets public.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for s3 bucket policy changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.SCP.001

**SCP Modifications Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.15; nist_800_53_r5: SI-4; soc2: CC7.2;

No CloudWatch metric filter and alarm for organizations:UpdatePolicy, DetachPolicy, and DeletePolicy events on Service Control Policies. SCP modifications change the organizational guardrails — an attacker who modifies an SCP can remove region restrictions, escalation prevention, or service protections. Requires CloudTrail organization-level trail in the management account.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching organizations:UpdatePolicy, organizations:DetachPolicy, and organizations:DeletePolicy events, then create an alarm with an SNS notification action. Requires an organization-level CloudTrail trail.

---

### CTL.CLOUDWATCH.MONITOR.SG.001

**Security Group Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.10; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor security group changes. Security group changes directly affect network access to resources.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for security group changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.STS.ANOMALOUS.001

**Anomalous STS Credential Usage Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12; owasp_nhi: NHI8; soc2: CC7.1;

CloudWatch alarms must detect STS credential usage from unexpected IP addresses or regions — indicating stolen instance role credentials being used externally.

**Remediation:** Create a CloudWatch metric filter matching STS API calls where the source IP is outside the expected VPC CIDR range or from unexpected regions. Alert on any match.

---

### CTL.CLOUDWATCH.MONITOR.TRAIL.001

**CloudTrail Configuration Changes Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.5; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor cloudtrail configuration changes. Changes to CloudTrail (CreateTrail, UpdateTrail, DeleteTrail, StopLogging) are the first action in covering tracks after compromise.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for cloudtrail configuration changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.TRAIL.ACCESS.001

**Unauthorized Access to CloudTrail Log Bucket Must Be Monitored**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-9; soc2: CC7.1;

CloudWatch alarms must detect access to the CloudTrail log bucket by principals other than the CloudTrail service. An attacker who reads log files can learn what's logged and plan evasion.

**Remediation:** Create a CloudWatch metric filter on the CloudTrail log group matching S3 GetObject/ListBucket events on the trail bucket where the principal is not cloudtrail.amazonaws.com. Create an alarm with SNS notification.

---

### CTL.CLOUDWATCH.MONITOR.TRUST.001

**Trust Policy Modifications Must Be Monitored**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.4; nist_800_53_r5: SI-4; owasp_nhi: NHI8; soc2: CC7.2;

No CloudWatch metric filter and alarm for iam:UpdateAssumeRolePolicy events. Trust policy modification changes who can assume a role — an attacker who modifies a trust policy adds themselves as a trusted principal. This is Rhino technique #14 (UpdateAssumeRolePolicy).

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching iam:UpdateAssumeRolePolicy events, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.UNAUTH.001

**Unauthorized API Calls Must Be Monitored**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.1; owasp_nhi: NHI8; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor unauthorized api calls. Unauthorized API calls (AccessDenied, UnauthorizedAccess) indicate credential probing or misconfigured IAM policies.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for unauthorized api calls, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.MONITOR.VPC.001

**VPC Changes Must Be Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 4.14; soc2: CC7.1;

A CloudWatch metric filter and alarm must monitor vpc changes. VPC lifecycle changes affect the entire network boundary.

**Remediation:** Create a CloudWatch log metric filter on the CloudTrail log group matching the CIS-specified pattern for vpc changes, then create an alarm with an SNS notification action.

---

### CTL.CLOUDWATCH.ORPHAN.DASHBOARD.001

**CloudWatch Dashboard Not Viewed in 90+ Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9; nist_800_53_r5: CM-2, SA-22; soc2: CC8.1;

CloudWatch dashboard exists but has not been viewed in 90+ days. The dashboard auto-refreshes on each load (API calls drive cost), shows metrics nobody consults, and may reference deleted alarms or metrics (ghost widgets that display empty panels). A dashboard nobody watches is governance clutter and a small but steady operational expense.

**Remediation:** Confirm no team or process depends on the dashboard (search internal documentation, on-call runbooks, and team wikis for the dashboard name or URL). If unused, delete: aws cloudwatch delete-dashboards --dashboard-names <name>. If the dashboard is still relevant but underused, surface it in team standups so the audience knows it exists.

---

### CTL.CLOUDWATCH.ORPHAN.LOGGROUP.SERVICE.001

**Log Group Exists for Decommissioned Service**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-8, SA-22; soc2: CC8.1;

CloudWatch Logs log group follows a standard service prefix (/aws/lambda/<function-name>, /aws/ecs/<cluster>, /aws/apigateway/<api>) but the corresponding service resource has been deleted. The log group keeps historical events from the deleted service and persists indefinitely unless explicitly deleted. Cost accrues, governance attention scales with the number of orphans, and the log group may be reused for an unrelated service later (confusing log content).

**Remediation:** Confirm the service resource (Lambda function, ECS cluster, API Gateway) was intentionally decommissioned. If logs are needed for compliance, archive to S3 (aws logs create-export-task) before deleting. Then delete: aws logs delete-log-group --log-group-name <name>. Note that the different service prefixes have different deletion patterns — Lambda log groups can auto-recreate when a function with the same name is redeployed, so deleting must coincide with confirming the function will not return.

---

### CTL.CLOUDWATCH.RETENTION.001

**CloudWatch Log Groups Must Have Retention Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); soc2: CC7.1;

CloudWatch Logs log groups must have a retention policy configured. Without a retention policy, logs are kept indefinitely (incurring cost) or may be deleted manually without audit trail.

**Remediation:** Set a retention policy on the log group. Run: aws logs put-retention-policy --log-group-name xxx --retention-in-days 365

---

### CTL.CLOUDWATCH.SUBSCRIPTION.CROSSACCOUNT.NOENCRYPT.001

**Subscription Filter Delivers to Cross-Account Destination Without Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-13; hipaa: 164.312(e)(1), 164.312(e)(2)(ii); iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: AU-9, SC-8, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

CloudWatch Logs subscription filter delivers log events to a destination in an external account — Kinesis stream, Lambda function, or Firehose — without encryption in transit or at rest at the destination. Log data crosses the account boundary in plaintext: any PII, credentials, security event details, or internal application data in the logs is accessible to the receiving account.

**Remediation:** Encrypt the destination: for Kinesis streams, enable server-side encryption with a CMK whose key policy is shared with the source account; for Lambda destinations, ensure the function encrypts its environment variables and any onward storage with a CMK; for Firehose, enable server-side encryption on the delivery stream and on the downstream S3 bucket. If sensitive fields can be redacted at the source, add a CloudWatch Logs Insights query or Lambda transformer that strips the fields before cross-account delivery.

---

### CTL.CLOUDWATCH.SUBSCRIPTION.CROSSACCOUNT.NOORG.001

**Subscription Filter Cross-Account Destination Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15; nist_800_53_r5: AC-3, AC-6, AU-9; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.6;

CloudWatch Logs subscription filter delivers to a destination in an external account whose policy does not include an aws:PrincipalOrgID condition or an explicit account allow-list. The destination accepts subscription deliveries from any account — meaning any AWS account, in or out of the organization, could establish a subscription to this destination and receive the log stream.

**Remediation:** Add an aws:PrincipalOrgID condition to the destination's resource policy (Kinesis KeyPolicy, Lambda function policy, Firehose delivery stream policy) restricting deliveries to principals within the organization. If cross-org delivery is genuinely needed, enumerate the specific accounts as Principal rather than leaving the policy open.

---

### CTL.CLOUDWATCH.SUBSCRIPTION.FILTER.NOALARM.001

**Subscription Filter Destination Has No Monitoring**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-5; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-5, SI-4; pci_dss_v4.0: 10.7; soc2: CC7.1, CC7.2;

CloudWatch Logs subscription filter delivers to a Kinesis stream or Lambda function, but the destination has no monitoring — no alarm for Kinesis throttling, no alarm for Lambda errors. If the destination is throttled or erroring, log events are silently dropped. The subscription filter continues matching events; the destination cannot process them; logs are lost between filter and destination with no signal to anyone.

**Remediation:** Add at least one alarm on the destination appropriate to its type: for Kinesis, WriteProvisionedThroughputExceeded > 0; for Lambda, Errors > 0 and Throttles > 0; for Firehose, DeliveryToS3.DataFreshness above the expected processing window. Wire the alarms into the same notification path used by other operational alerts so destination drops surface immediately rather than silently.

---

### CTL.CLOUDWATCH.SUBSCRIPTION.GHOST.FIREHOSE.001

**Subscription Filter References Deleted Kinesis Firehose**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-9, SI-4; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-9, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC8.1;

CloudWatch Logs subscription filter delivers log events to a Kinesis Data Firehose delivery stream that has been deleted. The filter matches log events; delivery fails; events are silently dropped before reaching the downstream destination (S3, Redshift, OpenSearch, Splunk). Extends the ghost reference family alongside the deleted-Kinesis and deleted-Lambda subscription destination controls.

**Remediation:** Either recreate the Firehose delivery stream with the same ARN, repoint the subscription filter at an existing Firehose, or delete the orphan filter: aws logs delete-subscription-filter --log-group-name <name> --filter-name <filter>. After fix, confirm by triggering a matching log event and verifying it lands in the Firehose's downstream destination.

---


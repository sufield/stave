# Control Reference — CLOUDTRAIL

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CLOUDTRAIL.ACCESS.LOGREAD.BROAD.001

**CloudTrail Log Files Accessible to Overly Broad Principals**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, AU-9; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

CloudTrail trail S3 bucket is readable by too many principals. Audit logs contain every API call — principal ARNs, source IPs, resource ARNs, parameters, timestamps. Broad read access to audit logs lets an insider or compromised principal map the entire infrastructure without making any API calls themselves (stealth reconnaissance), identify high-value targets, and time their actions against admin activity windows. Audit log read access should be limited to the security team and incident responders.

**Remediation:** Audit each principal in s3_read_principals. Remove read access from any principal that doesn't have a legitimate analysis or incident-response role. Replace bucket-wide reads with prefix-scoped reads where possible (e.g., a specific account's AWSLogs/<account-id>/ prefix for that account's security team). Reserve full bucket reads for the central security and IR teams.

---

### CTL.CLOUDTRAIL.ACCESS.STOPLOGGING.IAM.001

**IAM Principals Can Call StopLogging Without Admin Restriction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16, 4.5; fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, AU-9; owasp_nhi: NHI8; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant cloudtrail:StopLogging to non- administrative principals. StopLogging disables the audit trail — it should be restricted to a minimal set of security administrators. Each principal with StopLogging permission is a potential trail-disablement point: compromise that principal and the trail can be stopped. Counts principals reachable via explicit cloudtrail:StopLogging, cloudtrail:* (wildcard), or AdministratorAccess (grants everything including StopLogging).

**Remediation:** Audit each principal in stop_logging_principals: if they don't need StopLogging for legitimate maintenance, remove the permission. Replace AdministratorAccess attachments with scoped policies on developer/operator roles. Replace cloudtrail:* wildcards with the specific actions each role actually uses (typically cloudtrail:LookupEvents, cloudtrail:GetEventSelectors, cloudtrail:GetTrail). Reserve cloudtrail:StopLogging for a single security-admin role, gated behind MFA.

---

### CTL.CLOUDTRAIL.ALARM.DELETETRAIL.001

**No CloudWatch Alarm for CloudTrail DeleteTrail**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.5; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-9, AU-12, IR-4, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm monitors CloudTrail for DeleteTrail API calls. DeleteTrail permanently removes the trail configuration — S3 bucket reference, CW Logs reference, event selectors, everything. Unlike StopLogging (which preserves configuration), DeleteTrail requires recreating the entire trail to resume logging.

**Remediation:** Create a CloudTrail metric filter on eventName = DeleteTrail and a CloudWatch alarm with threshold 1 and a 60-second period; route to the same high-priority channel as the StopLogging alarm. DeleteTrail is rare in legitimate operations — any occurrence warrants immediate investigation.

---

### CTL.CLOUDTRAIL.ALARM.EVENTSELECTOR.001

**No CloudWatch Alarm for CloudTrail PutEventSelectors**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.5; fedramp_moderate: SI-4; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-9, AU-12, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm monitors CloudTrail for PutEventSelectors API calls. PutEventSelectors changes which events the trail records. An attacker can narrow the scope (switch to WriteOnly, drop data events for specific services) without stopping or deleting the trail. The trail keeps running. IsLogging stays true. The console shows an active trail. But the events that cover the attacker's actions are no longer captured. This is the stealthy form of trail tampering.

**Remediation:** Create a CloudTrail metric filter on eventName = PutEventSelectors and a CloudWatch alarm with threshold 1 and a 60-second period. Route to security on-call. Pair with a daily diff against the last-known-good selector configuration so any modification triggers immediate review.

---

### CTL.CLOUDTRAIL.ALARM.FAILEDLOGIN.001

**No CloudWatch Alarm for Failed Console Logins**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.6; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AC-7, AU-6, IR-4, SI-4; pci_dss_v4.0: 8.3, 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch metric filter and alarm monitors CloudTrail for failed ConsoleLogin events (events with errorMessage set). Failed logins indicate brute force, credential stuffing, or password spraying. Detection during the attack — before the attacker succeeds — enables MFA enforcement, lockout, or credential rotation in time. Companion to monitoring of successful logins (catches the attempts in flight, not the breach after).

**Remediation:** Create a CloudTrail metric filter on eventName = ConsoleLogin AND errorMessage IS NOT NULL, then a CloudWatch alarm with a threshold tuned to baseline noise (e.g., 5 failures per 5 minutes; tune by environment) and route to security on-call. Pair with IAM password policy lockout so repeated failures trigger account lockout in addition to alerting.

---

### CTL.CLOUDTRAIL.ALARM.GUARDDUTY.001

**No CloudWatch Alarm for GuardDuty Disablement**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.5; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, AU-9, IR-4, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch metric filter and alarm monitors CloudTrail for GuardDuty management events that disable detection — DeleteDetector, DisableOrganizationAdminAccount, StopMonitoringMembers, UpdateDetector with Enable=false. An attacker's first move after gaining admin access is often to disable GuardDuty so subsequent malicious activity is not flagged. Without an alarm, the disablement is invisible until threats stop being reported.

**Remediation:** Create a CloudTrail metric filter matching eventSource = guardduty.amazonaws.com AND eventName IN (DeleteDetector, DisableOrganizationAdminAccount, StopMonitoringMembers, UpdateDetector). CloudWatch alarm with threshold 1 and a 60-second period. Route to security on-call. Treat any GuardDuty disablement as a P0 — the attacker has admin and is preparing for further action.

---

### CTL.CLOUDTRAIL.ALARM.NATGW.001

**No CloudWatch Alarm for NAT Gateway Changes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2;

No CloudWatch metric filter and alarm monitors CloudTrail for CreateNatGateway or DeleteNatGateway events. NAT gateway creation in unexpected VPCs can indicate a data exfiltration setup (an attacker provisioning a NAT to route private-subnet traffic out) or unauthorized internet egress from sensitive subnets. Deletion can break legitimate egress unintentionally; either change warrants attention.

**Remediation:** Create a CloudTrail metric filter matching eventName IN (CreateNatGateway, DeleteNatGateway). CloudWatch alarm with threshold 1 over a 5-minute period; route to network on-call. Pair with a list of expected NAT gateway VPCs so the alarm response can quickly distinguish legitimate operations from suspicious provisioning.

---

### CTL.CLOUDTRAIL.ALARM.ORGCHANGE.001

**No CloudWatch Alarm for AWS Organizations Changes**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-2, AU-6, SI-4, IR-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3, CC8.1;

No CloudWatch metric filter and alarm monitors CloudTrail for Organizations management events — LeaveOrganization, RemoveAccountFromOrganization, InviteAccountToOrganization, CreateAccount, CloseAccount. These events change the organizational boundary. An account that leaves the organization retains cross-account access (resource policies still grant by account ID) but escapes organizational governance (SCPs no longer apply).

**Remediation:** Create a CloudTrail metric filter matching eventSource = organizations.amazonaws.com AND eventName IN (LeaveOrganization, RemoveAccountFromOrganization, InviteAccountToOrganization, CreateAccount, CloseAccount). CloudWatch alarm with threshold 1 over a 60-second period; route to the organization administrator on-call. Pair with SCP enforcement so LeaveOrganization is denied except by a small privileged role.

---

### CTL.CLOUDTRAIL.ALARM.RESOURCEDELETION.001

**No CloudWatch Alarm for Bulk Resource Deletion Events**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4, CP-10; pci_dss_v4.0: 10.6, 12.10; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch metric filter and alarm monitors CloudTrail for bulk resource deletion — multiple DeleteDBInstance, TerminateInstances, DeleteFunction, DeleteTopic, DeleteQueue, PurgeQueue, or DeleteBucket events within a short window. Individual deletions are normal operations. Multiple deletions across services within minutes indicates ransomware, insider threat, compromised automation, or runaway cleanup script. A composite metric filter that counts deletion events across services with a threshold (e.g., >=5 in 10 minutes) detects mass destruction events.

**Remediation:** Create a CloudTrail metric filter that matches the union of destructive event names — eventName IN (DeleteDBInstance, TerminateInstances, DeleteFunction, DeleteTopic, DeleteQueue, PurgeQueue, DeleteBucket, ScheduleKeyDeletion) — emitting a counter. Wire a CloudWatch alarm with threshold >= 5 over a 10-minute period. Tune thresholds to baseline operational deletion volume; production environments rarely see 5+ deletions across services within minutes.

---

### CTL.CLOUDTRAIL.ALARM.S3POLICY.001

**No CloudWatch Alarm for S3 Bucket Policy Changes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: SI-4; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AU-6, SI-4; pci_dss_v4.0: 10.2, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch metric filter and alarm monitors CloudTrail for PutBucketPolicy, DeleteBucketPolicy, or PutBucketAcl events. A single PutBucketPolicy call can make a bucket public or grant cross-account access; PutBucketAcl can add public-read or public-read-write. Without an alarm, bucket access-control changes are invisible until the next periodic security scan. This control fills the gap between CTL.S3.PUBLIC.001 (detects the resulting state) and the API event that produced it.

**Remediation:** Create a CloudTrail metric filter matching eventName IN (PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl) and a CloudWatch alarm with threshold 1 over a 5-minute period. Route to security on-call. Pair with CTL.S3.PUBLIC.001 — the alarm catches the event, the state control catches the resulting public posture if the alarm response is delayed.

---

### CTL.CLOUDTRAIL.ALARM.STOPLOGGING.001

**No CloudWatch Alarm for CloudTrail StopLogging**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.5; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-9, AU-12, IR-4, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm monitors CloudTrail for StopLogging API calls. StopLogging is the single most dangerous CloudTrail API call: it disables the audit trail immediately, every API call afterward is unrecorded, and the trail's configuration remains intact (the console still shows the trail). Without an alarm, the audit infrastructure can be silently turned off. Companion to CTL.CLOUDTRAIL.STOP.DETECT.001 (which detects the resulting state); this control detects the EVENT, enabling minutes-level response.

**Remediation:** Create a CloudTrail metric filter on eventName = StopLogging and a CloudWatch alarm with threshold 1 over a 60-second period: aws logs put-metric-filter --filter-pattern '{ ($.eventName = "StopLogging") }' followed by aws cloudwatch put-metric-alarm. Route the alarm to a high-priority on-call channel; treat StopLogging as a P0 incident until proven otherwise.

---

### CTL.CLOUDTRAIL.CENTRAL.SAMEACCOUNT.001

**CloudTrail Trail S3 Bucket Is in the Same Account as Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AU-4, AU-9, AC-3; pci_dss_v4.0: 10.5, 10.7; soc2: CC7.1, CC7.2;

CloudTrail trail delivers log files to an S3 bucket in the same AWS account that the trail monitors. If the account is compromised, the attacker has access to both the resources AND the audit log — they can modify or delete log files to cover their tracks. Best practice is to deliver trail logs to a dedicated logging account with restricted access; compromising the production account doesn't grant access to the log account.

**Remediation:** Create a dedicated AWS account for audit logging and move the trail's S3 bucket there. Update the trail's S3BucketName to point at the logging-account bucket and update the bucket policy in the logging account to grant cloudtrail.amazonaws.com PutObject from the trail-account's trail ARN (with aws:SourceArn pinning per CTL.CLOUDTRAIL.S3.SOURCEARN.001). Restrict access to the logging account to a small security-team principal set; production-account IAM cannot reach the log bucket.

---

### CTL.CLOUDTRAIL.CONFIG.GLOBALEVENTS.001

**CloudTrail Trail Does Not Include Global Service Events**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-2; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.1, 10.2; soc2: CC7.1;

CloudTrail trail has IncludeGlobalServiceEvents set to false. Global service events come from services that operate globally rather than per-region — IAM, STS, CloudFront, Route 53. With global events excluded: IAM policy changes are not logged, STS AssumeRole calls are not logged, CloudFront distribution changes are not logged, and Route 53 record changes are not logged. These are among the most security-critical events. AWS multi-region trails default IncludeGlobalServiceEvents to true; this control catches single-region trails or multi-region trails where the flag has been explicitly flipped.

**Remediation:** Update the trail to include global service events: aws cloudtrail update-trail --name <trail> --include-global-service-events. For multi-region trails this is the default — the flag is only false when explicitly disabled. For single-region trails, enabling global events causes that trail to receive duplicate global events if any other trail in the account already does. The org pattern is one multi-region trail with global events enabled, and any per-region trails with global events disabled.

---

### CTL.CLOUDTRAIL.CWLOGS.001

**CloudTrail Trails Must Be Integrated with CloudWatch Logs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-6; hipaa: 164.312(b); nist_800_53_r5: AU-6; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

CloudTrail trails must be configured to deliver events to a CloudWatch Logs log group with active delivery. CloudTrail delivers events to S3 by default. CloudWatch Logs integration is a separate configuration that enables real-time metric filtering and alerting. Without it, all 17 CIS-required CloudWatch metric filter controls (CTL.CLOUDWATCH.MONITOR.*) evaluate an empty event stream — the filters exist, the alarms are configured, but nothing fires. This is a silent gap: all monitoring controls appear to pass individually while the event pipeline is broken. CTL.CLOUDTRAIL.ENABLED.001 verifies the trail is active. This control verifies the trail is delivering to CloudWatch Logs — the prerequisite for real-time monitoring.

**Remediation:** Configure the trail to deliver to a CloudWatch Logs log group via the CloudTrail console or update-trail API. Create or specify a log group and grant CloudTrail the cloudwatch:PutLogEvents permission via an IAM role. Verify delivery is active after configuration.

---

### CTL.CLOUDTRAIL.CWLOGS.ENCRYPT.001

**CloudTrail CloudWatch Logs Group Not Encrypted with CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24, A.8.15; nist_800_53_r5: AU-9, SC-12, SC-28; pci_dss_v4.0: 3.4.1, 10.5; soc2: CC6.7, CC7.1;

CloudTrail's CloudWatch Logs log group is not encrypted with a customer-managed KMS key. CloudWatch Logs encrypts log data at rest by default with an AWS-managed key, but without a CMK there's no key policy control, no usage audit trail, and no revocation capability. The audit log data in CW Logs — containing every API call — is encrypted with a key the organization doesn't control.

**Remediation:** Associate a customer-managed KMS key with the log group: aws logs associate-kms-key --log-group-name <log-group> --kms-key-id <cmk-arn>. Update the KMS key policy to grant logs.amazonaws.com permission to use the key for the log group's region. After the association, new log events are encrypted with the CMK; existing events remain encrypted with the previous key (re-encryption is not automatic).

---

### CTL.CLOUDTRAIL.CWLOGS.RETENTION.SHORT.001

**CloudTrail CloudWatch Logs Retention Too Short for Compliance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-11; hipaa: 164.312(b), 164.316(b)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-9, AU-11; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC7.1, A1.2;

CloudTrail's CloudWatch Logs log group has a retention period shorter than the applicable compliance requirement. The existing CTL.CLOUDTRAIL.RETENTION.001 checks whether a retention policy exists; this control checks whether the configured PERIOD meets compliance requirements. A 30-day retention satisfies "retention exists" but fails "retention meets HIPAA's 6-year minimum." Compliance-profile control: fires when the log group has retention set AND the configured days are shorter than required_retention_days.

**Remediation:** Update the log group's retention to meet or exceed required_retention_days: aws logs put-retention-policy --log-group-name <name> --retention-in-days <days>. Allowed retention values in CW Logs are discrete (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653) — pick the smallest value that meets compliance, or a longer one if multiple regimes apply (HIPAA's 2190 rounds up to 3653 in CW Logs allowed values).

---

### CTL.CLOUDTRAIL.DATA.DYNAMODB.001

**CloudTrail Must Log DynamoDB Data Events**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must include DynamoDB data events to log table-level operations (GetItem, PutItem, Query, Scan). Without this, data exfiltration from DynamoDB is invisible.

**Remediation:** Add DynamoDB data event selector to the trail: event category Data, resource type AWS::DynamoDB::Table, read/write type All.

---

### CTL.CLOUDTRAIL.DATA.LAMBDA.001

**CloudTrail Must Log Lambda Invocation Data Events**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must include Lambda data events to log function invocations. Without this, attacker execution via Lambda is invisible.

**Remediation:** Add Lambda data event selector to the trail: event category Data, resource type AWS::Lambda::Function, read/write type All.

---

### CTL.CLOUDTRAIL.DATAEVENTS.S3.001

**CloudTrail Data Events Not Enabled for Sensitive S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 3.11; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.1, 10.2, 10.3; soc2: CC7.1, CC7.2;

CloudTrail is not configured to log S3 data events (GetObject, PutObject, DeleteObject) for buckets tagged as sensitive, in compliance scope, or containing PII / PHI. Without S3 data events on these buckets there is no record of who accessed which objects — an attacker can download an entire sensitive bucket without any audit record. Enabling data events for ALL buckets is expensive; this control checks only the buckets that warrant the log volume.

**Remediation:** Add an S3 data-event selector to the trail with explicit ARN scope for the sensitive buckets: aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[{"Name":"S3 sensitive bucket data events",
   "FieldSelectors":[
     {"Field":"eventCategory","Equals":["Data"]},
     {"Field":"resources.type","Equals":["AWS::S3::Object"]},
     {"Field":"resources.ARN","StartsWith":["arn:aws:s3:::sensitive-bucket-1/","arn:aws:s3:::sensitive-bucket-2/"]}]}]'.
Identify sensitive buckets via tags (data_classification: pii / phi / restricted) or a catalog maintained alongside the trail config.

---

### CTL.CLOUDTRAIL.DATAREAD.001

**S3 Object Read Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.9; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data read events (GetObject). Read logging provides evidence of data access for PHI audit trails and breach investigation.

**Remediation:** Add S3 data read event selectors to the trail using advanced event selectors with readOnly=true.

---

### CTL.CLOUDTRAIL.DATAWRITE.001

**S3 Object Write Logging Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.8; fedramp_moderate: AU-3; gdpr: Art.30; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1.7; soc2: CC6.2;

CloudTrail must log S3 data write events (PutObject, DeleteObject). Without object-level write logging, individual object mutations are invisible to the audit trail.

**Remediation:** Add S3 data write event selectors to the trail using advanced event selectors with readOnly=false.

---

### CTL.CLOUDTRAIL.DISABLE.RECUR.001

**CloudTrail Must Not Be Stopped and Restarted Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-9; hipaa: 164.312(b); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

CloudTrail trail has been stopped and restarted more than once in 30 days. Stopping CloudTrail creates gaps in the audit record. Repeated stop/start cycles are the forensic signature of deliberate audit evasion across multiple attacker sessions — the attacker stops the trail, takes actions, restarts it, and repeats.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.CLOUDTRAIL.ENABLED.001

**CloudTrail Must Be Enabled in All Regions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.1; cis_aws_v3.0: 3.1; fedramp_moderate: AU-2; ffiec: ISH-4; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-2; nist_csf_2.0: DE.CM; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must be configured as a multi-region trail. A single-region trail misses API activity in other regions, leaving gaps in the audit record that prevent forensic investigation of unauthorized access.

**Remediation:** Update the trail to enable multi-region logging. Run: aws cloudtrail update-trail --name xxx --is-multi-region-trail

---

### CTL.CLOUDTRAIL.ENCRYPT.001

**CloudTrail Logs Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.7; cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC6.7;

CloudTrail logs must be encrypted at rest using a KMS customer-managed key. Default S3 encryption (SSE-S3) does not provide key revocation capability needed for breach response.

**Remediation:** Configure the trail to use a KMS key for log encryption. Run: aws cloudtrail update-trail --name xxx --kms-key-id arn:aws:kms:...

---

### CTL.CLOUDTRAIL.EVENTSELECTORS.001

**CloudTrail Must Use Advanced Event Selectors for Granular Logging**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-3; soc2: CC7.1;

CloudTrail trails should use advanced event selectors instead of basic event selectors. Basic selectors provide coarse control (all management events, all/none S3 data events). Advanced selectors allow per-resource-type filtering, field-level conditions, and exclude high-volume read operations that add cost without security value. A trail with only basic selectors either logs too much (cost) or too little (gaps).

**Remediation:** Convert the trail to use advanced event selectors with put-event-selectors --advanced-event-selectors. Define field selectors for readOnly, resources.type, and resources.ARN to control exactly which data events are logged.

---

### CTL.CLOUDTRAIL.GHOST.CWLOGS.001

**CloudTrail Trail CloudWatch Logs Group Does Not Exist**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-6, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.1, 10.6; soc2: CC7.1, CC7.2;

CloudTrail trail is configured to deliver events to a CloudWatch Logs log group that has been deleted. The trail may still deliver to S3 (batch, ~5-minute delay) but real-time metric filters and alarms break — they depend on events arriving in the log group within seconds. Every ALARM.* control in the catalog (root login, unauthorized API calls, VPC/SG/IAM/CT/Config changes, secret access failures, KMS key disablement) becomes non-functional because its data source is gone.

**Remediation:** Recreate the log group (aws logs create-log-group --log-group-name <name>) and reattach to the trail (aws cloudtrail update-trail --name <trail> --cloud-watch-logs-log-group-arn <arn> --cloud-watch-logs-role-arn <delivery-role>). Recreate every metric filter on the new log group — log groups don't preserve filters across recreation. Audit the recovery window: events between log group deletion and recreation never reached real-time detection, so any incident in that window must be reconstructed from the S3 logs (if they exist).

---

### CTL.CLOUDTRAIL.GHOST.CWROLE.001

**CloudTrail CloudWatch Logs Delivery Role Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.3; nist_800_53_r5: AU-6, AC-3, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.1, 10.5, 10.6; soc2: CC7.1, CC7.2;

CloudTrail trail is configured to deliver to CloudWatch Logs using an IAM role that has been deleted. The log group may exist; the trail may be running. But the delivery role — the credential CloudTrail uses to write to the log group — is gone. CW Logs delivery fails silently. Same effect as a deleted log group, different root cause: the log group still has its data path and retention; only the credential is missing. Recreating the role restores delivery without data loss.

**Remediation:** Recreate the role with a trust policy allowing cloudtrail.amazonaws.com to assume it and an inline policy granting logs:CreateLogStream and logs:PutLogEvents on the target log group, then update the trail to reference the new role (aws cloudtrail update-trail --name <trail> --cloud-watch-logs-role-arn <new-role-arn>). Verify delivery by triggering an API call and confirming new events arrive in the log group within a minute.

---

### CTL.CLOUDTRAIL.GHOST.S3BUCKET.001

**CloudTrail Trail S3 Bucket Does Not Exist**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.1, 3.4; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-2, AU-3, AU-6, CM-2, CM-3; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC7.2, CC8.1;

CloudTrail trail is configured to deliver log files to an S3 bucket that has been deleted. The trail is running — IsLogging is true, the configuration is intact — but every log-file delivery fails. Events are processed and dropped. The trail appears configured; the audit log is empty. This is the meta-infrastructure ghost: the audit layer itself has a broken reference, so every API call across every service goes unrecorded and every metric filter / alarm based on CloudTrail events is starved.

**Remediation:** Either (a) recreate the S3 bucket with a name matching the trail's S3BucketName and restore the original bucket policy granting cloudtrail.amazonaws.com s3:PutObject and s3:GetBucketAcl, or (b) repoint the trail at an existing audit bucket (aws cloudtrail update-trail --name <trail> --s3-bucket-name <existing-audit-bucket>). After repointing, verify delivery by triggering an API call and confirming a new log file appears in the bucket within five minutes. Audit S3 CloudTrail events for the period the bucket was missing — those events are permanently lost.

---

### CTL.CLOUDTRAIL.GHOST.SNSTOPIC.001

**CloudTrail Trail SNS Notification Topic Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, CM-2, CM-3, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

CloudTrail trail is configured to publish notifications to an SNS topic when new log files arrive in S3. The SNS topic has been deleted. Log file delivery notifications are silently lost. Downstream consumers — Lambda functions, SQS queues, SIEM ingestion pipelines — never receive the notification, so they never process the newly delivered logs.

**Remediation:** Either (a) recreate the SNS topic with the same name and reattach (aws cloudtrail update-trail --name <trail> --sns-topic-name <topic>) plus subscribers, or (b) repoint the trail at an existing notification topic, or (c) clear the SNS configuration if the notifications are no longer needed (aws cloudtrail update-trail --name <trail> --no-sns-topic-name) and switch downstream consumers to S3 EventBridge notifications instead.

---

### CTL.CLOUDTRAIL.INCOMPLETE.001

**Complete Data Required for CloudTrail Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudTrail properties. A safety assessment cannot be completed without trail configuration data.

**Remediation:** Ensure the extractor calls aws cloudtrail describe-trails and aws cloudtrail get-trail-status and maps the response to the audit_trail observation properties.

---

### CTL.CLOUDTRAIL.INSIGHTS.001

**CloudTrail Insights Must Be Enabled for Anomaly Detection**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

CloudTrail Insights must be enabled to detect anomalous API activity patterns — unusual call volumes or error rates that indicate automated reconnaissance or attack.

**Remediation:** Enable CloudTrail Insights (ApiCallRateInsight and ApiErrorRateInsight) on the trail via the CloudTrail console or PutInsightSelectors API.

---

### CTL.CLOUDTRAIL.INTEGRITY.DIGEST.SAMEBUCKET.001

**CloudTrail Log File Digest Files Stored in Same Bucket as Logs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.2; fedramp_moderate: AU-9; hipaa: 164.312(c)(1); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, SI-7; pci_dss_v4.0: 10.5; soc2: CC7.1;

CloudTrail log file validation digest files are stored in the same S3 bucket as the log files. Log file validation works by writing per-hour digest files containing hashes of the log files; integrity is verified by comparing log-file hashes to the digest hashes. If both live in the same bucket, an attacker who compromises the bucket can modify the log files, recompute the hashes, and update the digest files — integrity verification still passes on tampered data. Separate buckets with independent access controls raise the bar to compromising both. Fires only when log file validation is enabled (otherwise there are no digests to protect).

**Remediation:** Move the digest output to a dedicated bucket with stricter access controls. The trail config exposes a separate digest-bucket setting; once moved, restrict write access on the digest bucket to the CloudTrail service principal only and apply the same hardening pattern as the log bucket (Object Lock, MFA Delete, bucket-policy Deny). Verify integrity end-to-end after the move with `aws cloudtrail validate-logs --trail-arn <arn>`.

---

### CTL.CLOUDTRAIL.LAKE.ENCRYPT.001

**CloudTrail Lake Event Data Store Not Encrypted with CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; scs_c02: 4.9; soc2: CC6.1;

A CloudTrail Lake event data store uses the default AWS-managed key instead of a customer-managed KMS key. Without a CMK, the organization cannot control key rotation, revoke access via key policy, or meet compliance requirements that mandate customer- controlled encryption keys for audit data.

**Remediation:** Create a new event data store with a CMK: aws cloudtrail create-event-data-store --name <name> --kms-key-id <key-arn>. Existing data stores cannot change encryption after creation.

---

### CTL.CLOUDTRAIL.LAKE.RETENTION.001

**CloudTrail Lake Event Data Store Has Short Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-11; scs_c02: 4.9; soc2: CC7.4;

A CloudTrail Lake event data store has a retention period shorter than 365 days. Short retention limits forensic investigation capability and may violate compliance requirements that mandate audit log retention of one year or more.

**Remediation:** Update the event data store retention: aws cloudtrail update-event-data-store --event-data-store <arn> --retention-period 365.

---

### CTL.CLOUDTRAIL.LIGHTSAIL.BLIND.001

**CloudTrail Does Not Log Lightsail Management Events**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

CloudTrail is not configured to log Lightsail management events. If Lightsail management events are not logged, an attacker can create instances, open ports, create bucket access keys, and exfiltrate data through Lightsail without leaving an audit trail. Lightsail operates outside AWS Config — CloudTrail is the only detection surface for Lightsail API activity.

**Remediation:** Ensure event selectors include Lightsail management events. With advanced selectors, add eventSource = lightsail.amazonaws.com.

---

### CTL.CLOUDTRAIL.LOG.VALIDATION.001

**CloudTrail Log File Validation Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 3.2; mitre_attack: T1562.008; nist_800_53_r5: AU-9;

CloudTrail log file validation must be enabled to detect whether log files have been modified or deleted after delivery to S3. Without validation, forensic investigators cannot determine if logs were tampered with.

**Remediation:** aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation

---

### CTL.CLOUDTRAIL.LOOKUP.RESTRICT.001

**CloudTrail LookupEvents Must Be Restricted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1526; nist_800_53_r5: AU-9;

CloudTrail LookupEvents access must be restricted to security and administrative roles. Unrestricted LookupEvents access exposes 90 days of API activity patterns including which principals performed which actions, resource names, source IP addresses, and timestamps. Attackers use this to identify active service accounts, map API usage patterns, and time their actions to blend with normal activity.

**Remediation:** Restrict cloudtrail:LookupEvents to security and administrative roles only. Apply conditions such as aws:PrincipalTag to limit access. Consider using CloudTrail Lake with fine-grained query permissions instead of LookupEvents for audit workflows.

---

### CTL.CLOUDTRAIL.NETWORK.ACTIVITY.001

**CloudTrail Must Log Network Activity Events for VPC Endpoints**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail Network Activity event logging must be enabled to capture VPC endpoint data-plane events including anonymous S3 requests. AWS's April 2026 patch logs anonymous requests as Network Activity events, but only if this event type is enabled.

**Remediation:** Enable Network Activity events on the CloudTrail trail via PutEventSelectors with the networkActivity event category.

---

### CTL.CLOUDTRAIL.ORG.001

**CloudTrail Must Be Configured as Organization Trail**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-12; nist_800_53_r5: AU-12; soc2: CC7.1;

CloudTrail trails must be configured as AWS Organizations trails covering all member accounts. Account-level trails leave member accounts without centralized logging.

**Remediation:** Convert to an organization trail via the management account.

---

### CTL.CLOUDTRAIL.ORG.MEMBERCANSTOP.001

**Organization Member Accounts Can Stop or Delete Their Trail**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-9, AU-12; pci_dss_v4.0: 10.5, 10.7; soc2: CC7.1, CC7.2;

No Service Control Policy prevents organization member accounts from calling cloudtrail:StopLogging or cloudtrail:DeleteTrail. Even with an organization trail in place, a compromised member-account admin can disable their local trail copy or — if the account has its own trail — disable audit logging for that account entirely. An SCP with Deny on these actions (excluding a break-glass security-admin role) is the only way to prevent member-account principals from disabling logging.

**Remediation:** Attach an SCP to the organization (or the relevant OU) that denies cloudtrail:StopLogging, cloudtrail:DeleteTrail, cloudtrail:UpdateTrail, and cloudtrail:PutEventSelectors with a NotPrincipal excluding the security-admin role and the management account. Verify by attempting StopLogging from a member account's admin role — the call must fail with an SCP-denied error before reaching the API.

---

### CTL.CLOUDTRAIL.REPLICATION.001

**CloudTrail Logs Must Be Replicated to a Separate Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-9; nist_800_53_r5: AU-9; soc2: CC7.1;

CloudTrail log destination must have cross-account replication configured to a separate logging account. Without replication, compromising the trail-hosting account enables complete evidence destruction.

**Remediation:** Configure S3 replication on the trail bucket targeting a bucket in a separate logging account.

---

### CTL.CLOUDTRAIL.RETENTION.001

**CloudTrail Logs Must Be Retained Beyond 90 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.3; fedramp_moderate: AU-11; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-11; nist_csf_2.0: DE.AE; pci_dss_v4.0: 10.7.1; soc2: CC7.1;

CloudTrail trail must deliver logs to an S3 bucket or CloudWatch Logs group with a retention policy that preserves logs beyond the 90-day CloudTrail Events History window. Without long-term retention, forensic investigation of incidents older than 90 days is impossible.

**Remediation:** Configure the trail to deliver logs to an S3 bucket with a lifecycle policy that retains objects for at least 365 days. Alternatively, deliver logs to a CloudWatch Logs group with a retention policy of 365 days or more.

---

### CTL.CLOUDTRAIL.S3.LIFECYCLE.001

**CloudTrail Trail S3 Bucket Has No Lifecycle Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-11, CM-2; pci_dss_v4.0: 10.7; soc2: CC7.1, A1.2;

CloudTrail trail S3 bucket has no S3 lifecycle policy. Log files accumulate indefinitely with no transition to cheaper storage and no expiration. This is a cost and governance issue (logs grow unbounded) rather than a security issue, but unbounded retention often hides compliance gaps elsewhere — when nobody manages retention, nobody verifies it meets requirements.

**Remediation:** Add an S3 lifecycle policy to the trail bucket. A typical configuration: transition to STANDARD_IA after 30 days (cheaper storage for less-frequently-accessed older logs), GLACIER after 90 days, expire after the compliance retention period (1 year for SOC2 / PCI-DSS, 6 years for HIPAA). Apply the policy to the AWSLogs/ prefix specifically so non-log objects in the bucket aren't affected. Pair with CTL.CLOUDTRAIL.S3.LIFECYCLE.SHORT.001 — this control catches the absence; the SHORT control catches an expiration shorter than compliance requires.

---

### CTL.CLOUDTRAIL.S3.LIFECYCLE.SHORT.001

**CloudTrail Trail S3 Lifecycle Deletes Logs Before Compliance Requirement**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.1, 3.4; fedramp_moderate: AU-11; hipaa: 164.312(b), 164.316(b)(2)(i); iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AU-9, AU-11; pci_dss_v4.0: 10.5.1, 10.7; soc2: CC7.1, A1.2;

CloudTrail trail S3 bucket lifecycle policy deletes log files before the applicable compliance retention period. Common requirements: HIPAA 6 years (2190 days), PCI-DSS 1 year (365 days), SOC2 1 year (365 days), internal policies 1-3 years. If the lifecycle expires objects at 90 days but compliance requires 365, evidence is destroyed before the audit window closes. Compliance- profile control: fires only when compliance tags or a compliance profile are active AND the lifecycle is shorter than required.

**Remediation:** Update the lifecycle policy's expiration to meet or exceed the required_retention_days. Verify both storage-class transitions (legal — older logs to Glacier) and the final expiration. For workloads spanning multiple compliance regimes, set expiration to the longest required period (HIPAA's 2190 days overrides PCI-DSS's 365). Add a compliance tag (compliance: hipaa / pci-dss / soc2) on the bucket that the observation pipeline reads to populate required_retention_days for this control.

---

### CTL.CLOUDTRAIL.S3.MFADELETE.001

**CloudTrail Trail S3 Bucket Does Not Have MFA Delete Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(c)(1), 164.312(d); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, AU-11, IA-2; pci_dss_v4.0: 10.5, 10.7; soc2: CC6.1, CC7.1;

CloudTrail trail S3 bucket has versioning enabled but MFA Delete is not. Without MFA Delete, log files can be permanently deleted with IAM credentials alone — no MFA challenge. MFA Delete requires the root account's MFA device to confirm permanent object deletions, raising the bar for an attacker from "compromise an IAM principal with s3:DeleteObject" to "compromise IAM credentials AND physical access to the root MFA device." Fires only when versioning is enabled (MFA Delete only applies to versioned buckets); CTL.S3.VERSIONING.001 catches the underlying versioning gap.

**Remediation:** Enable MFA Delete on the trail bucket (root account required, console flow rather than CLI for the first-time setup): aws s3api put-bucket-versioning --bucket <trail-bucket> --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "<root-mfa-serial> <code>". Document the root MFA process in runbooks — operationally complex but the strongest single control against audit-log destruction. Pair with Object Lock (CTL.CLOUDTRAIL.S3.OBJECTLOCK.001) and a bucket-policy Deny (CTL.CLOUDTRAIL.S3.NODELETE.001) for layered protection.

---

### CTL.CLOUDTRAIL.S3.NODELETE.001

**CloudTrail Trail S3 Bucket Policy Does Not Deny DeleteObject**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(c)(1); iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-9, AU-11; pci_dss_v4.0: 10.5, 10.7; soc2: CC6.1, CC7.1;

CloudTrail trail S3 bucket policy does not include a Deny statement for s3:DeleteObject (and ideally s3:DeleteObjectVersion, s3:PutBucketPolicy, s3:DeleteBucketPolicy). S3 bucket policy Deny overrides IAM Allow, blocking deletion regardless of the principal's IAM permissions. Without an explicit Deny, any principal with sufficient IAM permissions can delete log files. Three independent log-protection mechanisms layer here: Object Lock (WORM), MFA Delete (MFA factor), and bucket-policy Deny (policy block). This control covers the policy-block layer.

**Remediation:** Add a Deny statement to the bucket policy covering s3:DeleteObject, s3:DeleteObjectVersion, s3:PutBucketPolicy, and s3:DeleteBucketPolicy. Scope the Deny with NotPrincipal to allow a small break-glass role (e.g., the audit administrator) so log-retention enforcement remains operable. Bucket-policy Deny overrides IAM Allow — even an admin role with s3:DeleteObject in IAM is blocked from deleting if the bucket policy denies them.

---

### CTL.CLOUDTRAIL.S3.OBJECTLOCK.001

**CloudTrail Trail S3 Bucket Does Not Have Object Lock Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-9; hipaa: 164.312(c)(1); iso_27001_2022: A.8.15, A.8.10; nist_800_53_r5: AU-9, AU-11, SC-28; pci_dss_v4.0: 10.5, 10.5.2; soc2: CC7.1, A1.2;

CloudTrail trail S3 bucket does not have S3 Object Lock enabled. Without Object Lock, log files can be deleted or overwritten after delivery. An attacker who gains access to the trail S3 bucket can erase specific log files (removing evidence) or overwrite log files with modified versions (altering the audit record). Object Lock in Compliance mode provides WORM (Write Once Read Many) protection — log files cannot be deleted or overwritten for the retention period, even by the root account.

**Remediation:** Recreate the audit bucket with Object Lock enabled (S3 requires Object Lock to be set at bucket creation time) and migrate log files to it; update the trail's S3BucketName. Configure a default Object Lock retention rule in Compliance mode for the audit horizon (e.g., 365 days for typical compliance, 7 years for highly regulated workloads). Compliance mode is preferred over Governance — Governance allows privileged users to override the lock.

---

### CTL.CLOUDTRAIL.S3.SOURCEARN.001

**CloudTrail Trail S3 Bucket Policy Does Not Validate SourceArn**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.15; nist_800_53_r5: AC-3, AU-9, AU-10; pci_dss_v4.0: 10.5, 7.1; soc2: CC6.1, CC6.6, CC7.1;

CloudTrail trail S3 bucket policy allows s3:PutObject from the cloudtrail.amazonaws.com service principal without restricting aws:SourceArn to the specific trail(s) that should deliver to this bucket. Without SourceArn validation, any CloudTrail trail in any AWS account can write to this bucket — including an attacker's trail writing fake log entries.

**Remediation:** Update the bucket policy's CloudTrail PutObject statement to require aws:SourceArn matching the organization's trail ARN(s). For an org trail use the multi-region trail ARN; for member-account trails list each. The condition shape: "Condition":{"StringEquals":{"aws:SourceArn":[
  "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail"]}}.
Verify by attempting to write from a test trail in a different account — the write must fail with AccessDenied citing the SourceArn condition.

---

### CTL.CLOUDTRAIL.S3LOG.001

**CloudTrail S3 Bucket Must Have Access Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.4; fedramp_moderate: AU-9; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.5.1; soc2: CC7.1;

The S3 bucket receiving CloudTrail logs must have server access logging enabled. Without it, access to the audit logs themselves is not auditable.

**Remediation:** Enable access logging on the trail S3 bucket: aws s3api put-bucket-logging --bucket <trail-bucket> --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"<log-bucket>"}}'

---

### CTL.CLOUDTRAIL.STATE.MGMT.WRITEONLY.001

**CloudTrail Trail Logs Only Write Management Events**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.1; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-12; pci_dss_v4.0: 10.1, 10.2; soc2: CC7.1, CC7.2;

CloudTrail trail event selectors are configured to log only WriteOnly management events. Read events — DescribeInstances, GetSecretValue, ListBuckets, AssumeRole — are not recorded. An attacker performing reconnaissance is invisible: only write actions appear in the audit trail. The reconnaissance phase, where the attacker maps the environment before acting, has no audit record at all.

**Remediation:** Update the trail's event selectors to include both Read and Write management events (aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[{"ReadWriteType":"All", "IncludeManagementEvents":true,"DataResources":[]}]'). The volume increase is real but the cost is bounded — management events are far less frequent than data events.

---

### CTL.CLOUDTRAIL.STOP.DETECT.001

**CloudTrail Trails Must Be Actively Logging in All Regions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(b); mitre_attack: T1562.008; nist_800_53_r5: AU-12;

CloudTrail must be actively logging and configured as a multi-region trail. Stopping CloudTrail is the first action attackers take after gaining access — it eliminates the audit trail of subsequent actions.

**Remediation:** aws cloudtrail start-logging --name <trail-name> aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail

---

### CTL.CLOUDTRAIL.VALIDATION.001

**CloudTrail Log File Validation Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.2; cis_aws_v3.0: 3.2; fedramp_moderate: AU-9; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-9; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

CloudTrail must have log file integrity validation enabled. Without validation, an attacker who gains access to the log bucket can modify or delete log entries to cover their tracks.

**Remediation:** Enable log file validation on the trail. Run: aws cloudtrail update-trail --name xxx --enable-log-file-validation

---


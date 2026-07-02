# Control Reference — CONFIG

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CONFIG.ACCESS.DELETERECORDER.BROAD.001

**config:DeleteConfigurationRecorder Granted to Broad Principals**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16, 3.5; fedramp_moderate: AC-3, AC-6, CM-5; hipaa: 164.312(a)(1), 164.312(b); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant config:DeleteConfigurationRecorder to non- administrative principals. DeleteConfigurationRecorder is the permanent counterpart to StopConfigurationRecorder — instead of stopping the recorder (recoverable), it deletes the recorder configuration entirely (recoverable only by recreation). Once deleted, no resource configurations are recorded; the configuration audit trail has no future entries until a new recorder is created. The permission should be tightly restricted to security administrators and protected by SCP at the org level.

**Remediation:** Audit IAM policies for config:Delete*, config:DeleteConfigurationRecorder, and config:* on Resource: *. Restrict the permission to a dedicated security-admin role. Pair with an SCP at the org level that denies DeleteConfigurationRecorder for all member accounts (the existing CTL.CONFIG.ACCESS.NOSCP.001 covers that).

---

### CTL.CONFIG.ACCESS.DELETERULE.BROAD.001

**config:DeleteConfigRule Granted to Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant config:DeleteConfigRule to non-administrative principals. DeleteConfigRule removes compliance evaluation rules — a principal with this permission can delete rules that detect non-compliance, effectively removing compliance checks rather than stopping the recorder.

**Remediation:** Audit IAM policies for config:DeleteConfigRule and config:* on Resource: *. Restrict to compliance-admin and security-admin roles. For high-stakes rules, require a manual approval step (e.g., a Lambda authorizer or SCP requiring an MFA condition) before deletion is allowed.

---

### CTL.CONFIG.ACCESS.NOSCP.001

**No SCP Prevents Member Accounts From Stopping or Modifying Config**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16, 3.5; fedramp_moderate: AC-3, AC-6, CM-5; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC8.1;

AWS Organization has Config recording in member accounts but no Service Control Policy (SCP) denies the destructive Config permissions (config:StopConfigurationRecorder, config:DeleteConfigurationRecorder, config:DeleteConfigRule, config:PutConfigurationRecorder) at the org level. Without an SCP, member-account IAM policies are the only barrier — and a member-account admin can grant themselves any IAM permission they want. The organizational baseline that "all member accounts have Config recording" is enforceable only at the org boundary; SCPs are that boundary.

**Remediation:** Author and attach an SCP at the organizational unit (OU) or root level that explicitly denies config:StopConfigurationRecorder, config:DeleteConfigurationRecorder, config:DeleteConfigRule, config:PutConfigurationRecorder, and config:PutDeliveryChannel for all principals in the OU. AWS publishes sample SCPs for this exact case. Pair with the existing CTL.IAM.SCP.CONFIG.001 control if it covers the SCP-existence side; this control catches the absence at the Config-account level.

---

### CTL.CONFIG.ACCESS.PUTRECORDER.BROAD.001

**config:PutConfigurationRecorder Granted to Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16, 3.5; fedramp_moderate: AC-3, AC-6, CM-5; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant config:PutConfigurationRecorder to non- administrative principals. PutConfigurationRecorder modifies the recorder's scope (which resource types it records, whether it includes global resources, recording mode). An attacker with this permission narrows the recorder's scope to exclude resource types they intend to abuse — drops S3 from the recorded list, drops IAM from global recording — and the recorder continues appearing healthy while specific resource types are silently no longer recorded. The attacker's actions on the dropped types are invisible to Config.

**Remediation:** Audit IAM policies for config:PutConfigurationRecorder, config:Put*, and config:* on Resource: *. Restrict the permission to a dedicated security-admin role. Pair with an SCP at the org level that denies PutConfigurationRecorder for all member accounts. Any legitimate operator who needs to adjust recorder scope should do so through the security-admin role with change-management documentation.

---

### CTL.CONFIG.ACCESS.PUTREMEDIATION.BROAD.001

**config:PutRemediationConfigurations Granted to Broad Principals**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16, 3.5; fedramp_moderate: AC-3, AC-6, CM-5; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 12.10; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant config:PutRemediationConfigurations to non- administrative principals. The permission modifies the remediation actions tied to Config rules — what runs when a rule fires non-compliant, with what role, against what target, with what parameters. An attacker with this permission rewrites the remediation to a no-op, to an action that ignores specific resources, or to one that uses a less-privileged role; the rule still fires non-compliant but the remediation no longer corrects the state. Auto-remediation appears configured; enforcement is hollow.

**Remediation:** Audit IAM policies for config:PutRemediationConfigurations, config:Put*, and config:* on Resource: *. Restrict the permission to a dedicated security-admin role. Remediation changes should go through the same change-control process as rule definitions — production remediation is part of the compliance enforcement layer and shouldn't be casually mutable.

---

### CTL.CONFIG.ACCESS.STOPRECORDER.BROAD.001

**config:StopConfigurationRecorder Granted to Broad Principals**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16, 3.5; fedramp_moderate: AC-3, AC-6, CM-5; hipaa: 164.312(a)(1), 164.312(b); iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5, SI-4; pci_dss_v4.0: 7.1, 7.2, 10.5; soc2: CC6.1, CC6.3, CC7.1;

IAM policies grant config:StopConfigurationRecorder to non- administrative principals. StopConfigurationRecorder disables Config recording — the Config equivalent of CloudTrail's StopLogging. Any principal with this permission can blind the configuration audit trail.

**Remediation:** Audit IAM policies for config:Stop*, config:StopConfigurationRecorder, and config:* on Resource: *. Restrict the permission to a dedicated security-admin role. Pair with an SCP at the org level that denies StopConfigurationRecorder for all member accounts (the existing CTL.IAM.SCP.CONFIG.001 covers that).

---

### CTL.CONFIG.AGGREGATOR.INCOMPLETE.ACCOUNTS.001

**Config Aggregator Excludes Member Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CA-7, CM-8; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-8; pci_dss_v4.0: 10.1; soc2: CC7.1, CC8.1;

Config aggregator exists but does not include all member accounts. The centralized compliance dashboard shows results for the included accounts only — missing accounts have no visibility in the aggregator. The view is presented as complete and is silently incomplete.

**Remediation:** Switch to organization-wide aggregation instead of explicit account lists so new accounts auto-include: aws configservice put-configuration-aggregator --organization-aggregation-source RoleArn=<role>,AllAwsRegions=true. If explicit account lists are required, add the missing accounts and verify aggregator status returns to OUTPUT_ACTIVE.

---

### CTL.CONFIG.AGGREGATOR.INCOMPLETE.REGIONS.001

**Config Aggregator Excludes Regions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-8; pci_dss_v4.0: 10.1; soc2: CC7.1, CC8.1;

Config aggregator exists but does not include all enabled AWS regions. Resources created in excluded regions are invisible in the aggregated view. An attacker can create resources in an unmonitored region to evade the centralized compliance view.

**Remediation:** Set the aggregator to AllAwsRegions=true: aws configservice put-configuration-aggregator --account-aggregation-sources AccountIds=...,AllAwsRegions=true (or for organization aggregation, --organization-aggregation-source RoleArn=...,AllAwsRegions=true). For accounts where some regions are intentionally never used, document the exclusion in change management; do not rely on aggregator scope as a region blocker.

---

### CTL.CONFIG.AGGREGATOR.NONE.001

**No Config Aggregator Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CA-7, CM-8; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-8; pci_dss_v4.0: 10.1; soc2: CC7.1, CC8.1;

AWS Organizations is in use but no Config aggregator exists. Each account and region stores Config data independently; security teams must query Config in each account and region individually to assess organizational compliance posture.

**Remediation:** Create a Config aggregator in the security or audit account: aws configservice put-configuration-aggregator --configuration-aggregator-name org-aggregator --organization-aggregation-source RoleArn=<role>,AllAwsRegions=true. Use organization-wide collection so new accounts are auto-included.

---

### CTL.CONFIG.CONFORMANCE.NONE.001

**AWS Config Account Has No Conformance Pack Deployed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: CA-2, CA-7, CM-6; iso_27001_2022: A.5.36, A.8.9; nist_800_53_r5: CA-2, CA-7, CM-6; pci_dss_v4.0: 12.4; soc2: CC7.1, CC7.2, CC8.1;

AWS Config records resource configurations in the account, but no conformance pack is deployed. Conformance packs are bundles of Config rules organized around a compliance framework — CIS AWS Foundations, NIST 800-53, PCI-DSS, HIPAA, FedRAMP. Without one, compliance evaluation depends on whatever ad-hoc rules the operator added. Most accounts hosting regulated workloads need at least one conformance pack as the baseline set of evaluations; without it, "we use Config for compliance" is half-true.

**Remediation:** Deploy a conformance pack matching the account's compliance obligations: aws configservice put-conformance-pack --conformance-pack-name <name> with the appropriate template (AWS publishes sample-templates for CIS, NIST 800-53, PCI-DSS, HIPAA, FedRAMP, and others). Pair the pack with monitoring on the pack's compliance score so degradation surfaces.

---

### CTL.CONFIG.CONFORMANCE.PARAMS.WEAKENED.001

**Conformance Pack Parameter Overrides Weaken Pack Defaults**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: CA-2, CA-7, CM-6; iso_27001_2022: A.5.36, A.8.9; nist_800_53_r5: CA-2, CA-7, CM-6, SI-4; pci_dss_v4.0: 12.4; soc2: CC7.1, CC8.1;

AWS Config conformance pack is deployed with parameter overrides that loosen the pack template's default values. Common shapes: the pack's password-age rule defaulted to 90 days but is overridden to 365; the encryption rule defaulted to required-for- S3 but is overridden to optional; the MFA rule defaulted to required-for-all-IAM-users but is overridden to required-for-root-only. The pack name in the inventory still matches the framework, but the actual rule parameters no longer enforce the framework's thresholds.

**Remediation:** Audit the pack's input parameters against the published template defaults: aws configservice describe-conformance-packs --conformance-pack-names <name>; compare ConformancePackInputParameters against the pack template values. Restore parameters that match the framework's intent, or redeploy the pack from the original template: aws configservice put-conformance-pack with the unmodified template URI. Document any deliberately- looser parameter as a triage override with the operational rationale.

---

### CTL.CONFIG.CONFORMANCE.RULES.DISABLED.001

**Conformance Pack Has Disabled Rules Within It**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: CA-2, CA-7, CM-6; iso_27001_2022: A.5.36, A.8.9; nist_800_53_r5: CA-2, CA-7, CM-6; pci_dss_v4.0: 12.4; soc2: CC7.1, CC7.2, CC8.1;

AWS Config conformance pack is deployed but one or more rules within the pack are in DELETING / inactive state, or were individually disabled after deployment. The pack's compliance score continues to compute against the active subset; the disabled rules don't appear in non-compliant counts even though their checks aren't running. Operators see "pack deployed" and assume the full rule set is evaluating; the disabled rules silently produce zero evidence.

**Remediation:** Inspect the pack's rule set: aws configservice describe-conformance-pack-status, then describe-config-rules for each rule the pack defines. Re-enable any rule in DELETING or non-ACTIVE state, or redeploy the pack: aws configservice put-conformance-pack --conformance-pack-name <name> --template-s3-uri <uri>. Audit who disabled the rule (CloudTrail) — pack-rule disables are usually deliberate; verify the rationale.

---

### CTL.CONFIG.CONFORMANCE.SCORE.UNMONITORED.001

**Conformance Pack Compliance Score Has No Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AU-6, CA-7, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, CA-7, SI-4; pci_dss_v4.0: 10.4, 12.4; soc2: CC7.1, CC7.2, CC8.1;

AWS Config conformance pack is deployed but no CloudWatch alarm watches its compliance score. The score is the percentage of evaluated resources judged compliant against the pack's rules — the headline metric for framework alignment. Without an alarm, score degradation (a rule starts producing non-compliant results, the percentage drops) is invisible until a human happens to view the pack's dashboard. By then the non-compliance has been live for whatever the human-review interval is, which is typically much longer than the operator imagines.

**Remediation:** Create a CloudWatch alarm on the AWS/Config namespace ComplianceByConfigRule metric, dimensioned by ComplianceType=NON_COMPLIANT and the conformance pack's rule names. Or put a metric filter on the pack's compliance score and alarm on threshold breach: aws cloudwatch put-metric-alarm with the pack-score metric. Alarm targets should reach the team owning the pack — pack owners are typically compliance or security, not generic SRE.

---

### CTL.CONFIG.DELIVERY.FAILURES.UNMONITORED.001

**Config Delivery Failures Not Monitored**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, AU-9, IR-4, SI-4; pci_dss_v4.0: 10.5, 10.6; soc2: CC7.1, CC7.2;

AWS Config delivery failures (S3 write failures, SNS publish failures) are not monitored by any CloudWatch alarm. When delivery fails, Config records internally but cannot persist to S3 or notify via SNS. The configuration audit trail silently stops being persisted.

**Remediation:** Create a CloudWatch alarm on the AWS/Config metrics ConfigDeliveryFailed and ConfigSnapshotDeliveryFailed with threshold > 0 over a short evaluation window. Wire the alarm to the security operations SNS topic. Pair with the existing LIFECYCLE.SNAPSHOT.STALE control so persistence-pipeline issues surface both at the metric level (FAILURES.UNMONITORED) and at the staleness level (SNAPSHOT.STALE).

---

### CTL.CONFIG.DELIVERY.NOSNS.001

**Config Delivery Channel Has No SNS Topic Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

AWS Config delivery channel exists but no SNS topic is configured. Recording continues, S3 delivery may continue, but no real-time notification of resource configuration changes is published. Subscribers receive nothing; remediation automation cannot trigger.

**Remediation:** Create an SNS topic for Config notifications, grant config.amazonaws.com publish permission, and configure the delivery channel: aws configservice put-delivery-channel --delivery-channel name=<name>,s3BucketName=<bucket>,snsTopicARN=<topic-arn>. Subscribe Lambda for auto-remediation, the security paging topic for incident response, and a SQS queue for downstream processing.

---

### CTL.CONFIG.DELIVERY.NOTCHANNEL.001

**No Config Delivery Channel Configured**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5, 3.6; fedramp_moderate: AU-9, CM-8; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, CM-3, CM-8; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC8.1;

AWS Config recorder exists but no delivery channel is configured. Configuration data is recorded in Config's internal buffer but not persisted to S3 (no long-term history) and not published to SNS (no real-time notifications). Any audit trail beyond Config's internal retention is lost.

**Remediation:** Create a delivery channel with at minimum an S3 bucket: aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=<bucket>. Add an SNS topic if real-time notifications are needed. Verify the next configuration history file lands in the bucket and confirm Config rules begin evaluating.

---

### CTL.CONFIG.DELIVERY.S3.NODELETE.001

**Config Delivery S3 Bucket Policy Does Not Deny DeleteObject**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: AU-9, CM-3; hipaa: 164.312(b), 164.312(c)(1); iso_27001_2022: A.8.10, A.8.15; nist_800_53_r5: AU-9, AU-11, CM-3; pci_dss_v4.0: 10.5; soc2: CC6.1, CC7.1;

AWS Config delivery S3 bucket policy does not include a Deny statement for s3:DeleteObject. Without explicit Deny, any principal with sufficient IAM permissions can delete Config configuration history files — erasing the configuration audit trail. Same protection pattern as CloudTrail's S3 bucket Deny requirement.

**Remediation:** Add a Deny statement to the bucket policy: "Effect": "Deny", "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"], "Resource": "arn:aws:s3:::<bucket>/AWSLogs/*/Config/*", "Principal": "*". Combine with bucket versioning and Object Lock in compliance mode for stronger immutability. The same deny should apply to lifecycle expiration rules that would delete historical files on schedule.

---

### CTL.CONFIG.ENABLED.001

**AWS Config Must Be Recording All Resource Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v1.4.0: 3.5; cis_aws_v3.0: 3.3; fedramp_moderate: CM-2; ffiec: CAT-D3; gdpr: Art.30; hipaa: 164.312(b); iso_27001_2022: A.8.9; nist_800_53_r5: CM-2; nist_csf_2.0: PR.PS; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

AWS Config must be enabled and recording all supported resource types. Without Config, configuration changes are not tracked and drift from the desired security baseline cannot be detected.

**Remediation:** Enable the Config recorder with all resource types. Run: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:...,recordingGroup={allSupported=true}

---

### CTL.CONFIG.GHOST.DELIVERY.S3.001

**Config Delivery Channel S3 Bucket Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-9, CM-2; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, CM-2, CM-3; pci_dss_v4.0: 10.5; soc2: CC7.1, CC8.1;

AWS Config delivery channel references an S3 bucket that has been deleted. Config records configuration snapshots and history files but cannot deliver them. The configuration audit trail is lost; existing data in the deleted bucket is gone permanently.

**Remediation:** Recreate the S3 bucket with the Config bucket policy that grants config.amazonaws.com PutObject permission (and Deny DeleteObject — see DELIVERY.S3.NODELETE), or repoint the delivery channel at an existing bucket: aws configservice put-delivery-channel --delivery-channel name=<name>,s3BucketName=<bucket>. After fix, validate the next configuration history file lands in the bucket.

---

### CTL.CONFIG.GHOST.DELIVERY.SNS.001

**Config Delivery Channel SNS Topic Deleted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.1, CC7.2;

AWS Config delivery channel references an SNS topic that has been deleted. Config publishes configuration change notifications to the SNS topic, but the topic does not exist — notifications go nowhere. Real-time awareness of configuration drift is lost while recording and S3 delivery may continue.

**Remediation:** Recreate the SNS topic with the Config publish permission, or repoint the delivery channel at an existing topic: aws configservice put-delivery-channel --delivery-channel name=<name>,snsTopicARN=<topic-arn>. Verify by triggering a configuration change (tag a resource) and confirming the notification reaches subscribers.

---

### CTL.CONFIG.GHOST.RECORDER.ROLE.001

**Config Recorder IAM Role Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CM-2, CM-8; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CM-2, CM-3, CM-8, SA-10; pci_dss_v4.0: 10.1, 11.5; soc2: CC7.1, CC8.1;

AWS Config configuration recorder has an IAM role that has been deleted. The recorder exists with role ARN configured; the role itself does not exist. Config cannot assume the role, cannot read resource configurations, and recording stops silently. Every Config rule, every conformance pack, every compliance evaluation depends on this single role.

**Remediation:** Recreate the IAM role with the AWSConfigServiceRolePolicy or repoint the recorder at the AWS service-linked role (AWSServiceRoleForConfig) — the latter is auto-managed and avoids the ghost-role failure mode entirely. Update via aws configservice put-configuration-recorder --configuration-recorder name=<name>,roleARN=<role>. After fix, confirm the recorder status returns to recording and the next configuration history file lands in the delivery bucket.

---

### CTL.CONFIG.INCOMPLETE.001

**Complete Data Required for AWS Config Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required AWS Config properties.

**Remediation:** Ensure the extractor calls aws configservice describe-configuration-recorders and aws configservice describe-config-rules.

---

### CTL.CONFIG.LIFECYCLE.REMEDIATION.NEVEREXECUTED.001

**Config Remediation Has Never Executed Despite Non-Compliance**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CM-3, CM-4, SI-7; soc2: CC7.2, CC8.1;

AWS Config remediation is configured for a rule that has non-compliant resources, but the remediation has never executed. Either remediation is set to manual (requires human trigger), auto-remediation is disabled, or the trigger condition does not match the rule's evaluation output. The fix path is configured and unused.

**Remediation:** Confirm that auto-remediation is enabled on the rule (not set to manual). If manual is intentional, document the human-trigger process and run a test execution to verify the SSM document and role work end-to-end. If auto is intended but the remediation never fires, check that the remediation's trigger condition matches the rule's evaluation output (some rules don't auto- trigger remediation if their result is NOT_APPLICABLE rather than NON_COMPLIANT).

---

### CTL.CONFIG.LIFECYCLE.RULE.NEVERTRIGGERED.001

**Config Rule Has Never Evaluated Any Resource**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-2, CM-3, SA-22; soc2: CC8.1;

AWS Config rule has been configured for at least 30 days but has never produced an evaluation result. Either the rule's scope doesn't match any existing resource type, the recorder doesn't record the resource type the rule evaluates, or the rule is change- triggered for resources that have not changed. Dead compliance configuration regardless of cause.

**Remediation:** Inspect the rule's scope and resource_scope_resource_type. If no resources of that type exist in the account, delete the rule (it's not applicable). If resources of that type exist, check whether the recorder is configured to record that type (NOTALLRESOURCES). If both are correct, the rule may be change-triggered for resources that haven't changed since rule creation — trigger a manual evaluation: aws configservice start-config-rules-evaluation --config-rule-names <rule>.

---

### CTL.CONFIG.LIFECYCLE.SNAPSHOT.STALE.001

**Config Configuration Snapshots Not Delivered in 30+ Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-9, CA-7; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, CA-7, CM-2, SI-4; pci_dss_v4.0: 10.1, 10.5; soc2: CC7.1, CC7.2, CC8.1;

AWS Config has not delivered a configuration snapshot to S3 in more than 30 days. Snapshots are full resource inventories at a point in time. Configuration history files (per-resource changes) may still be delivered, but the durable full-inventory baseline is stale.

**Remediation:** Inspect Config delivery channel status: aws configservice describe-delivery-channel- status. If delivery is failing, fix the underlying issue (S3 permission, deleted bucket, KMS key inaccessible). After fix, trigger a manual snapshot delivery: aws configservice deliver-config-snapshot --delivery-channel-name <name>. Confirm the next snapshot lands in S3.

---

### CTL.CONFIG.ORG.AGGREGATOR.UNENCRYPTED.001

**Cross-Account Config Aggregator Storage Not Encrypted With Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: SC-12, SC-28, AU-9; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28, AU-9; pci_dss_v4.0: 3.5, 10.5; soc2: CC6.1, CC6.7;

AWS Config aggregator collects configuration data from multiple accounts and regions, but the underlying S3 bucket holding aggregated data is encrypted with the AWS-managed key (default) rather than a customer-managed KMS key. The aggregator data spans every member account — IAM policies, security group rules, encryption keys, network configuration — the highest-sensitivity inventory in the organization. AWS-managed encryption is opaque to the customer: no per-key access policy, no CloudTrail decrypt trail, no customer-side revocation. Customer-managed KMS keys are the standard for cross- account audit data.

**Remediation:** Reconfigure the aggregator's storage S3 bucket to use a customer-managed KMS key: aws s3api put-bucket-encryption with SSEAlgorithm=aws:kms and the appropriate KMSMasterKeyID. The KMS key policy must allow the Config service principal (and aggregator source accounts) to encrypt; the central audit account holds key- administration. Existing aggregator objects remain encrypted under whatever key was active when they were written.

---

### CTL.CONFIG.ORG.AUDIT.COLOCATED.001

**Member Account Config Data Delivered to Bucket in Management Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6, AU-9, CM-5; iso_27001_2022: A.5.15, A.5.18, A.8.15; nist_800_53_r5: AC-3, AC-6, AU-9, CM-5; pci_dss_v4.0: 10.5, 7.1; soc2: CC6.1, CC6.3, CC7.2, CC8.1;

Member account Config delivery channel points at an S3 bucket owned by the management account. The configuration audit trail for member accounts is co-located with the management account's resources — billing, root user, top-level IAM, organization configuration. A compromise of the management account reaches both the audited resources (the organization itself) and the audit data (the configuration history of every member account). AWS best-practice guidance is to deliver Config data to a dedicated security or audit account outside the management account, so identity compromises don't cascade across the audit boundary.

**Remediation:** Stand up a dedicated security or audit account in the organization. Create the Config delivery destination bucket in that account, with bucket policy allowing each member account's Config service principal to write. Reconfigure each member account's delivery channel: aws configservice put-delivery-channel --delivery-channel name=<name>, s3BucketName=<audit-account-bucket>, s3KmsKeyArn=<audit-account-cmk>. The delivery role in the member account needs permission to write to the audit account's bucket.

---

### CTL.CONFIG.ORG.MEMBERCANOVERRIDE.001

**Member Accounts Can Override Organization Config Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-5, CM-6; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CM-5, CM-6; pci_dss_v4.0: 11.5; soc2: CC7.1, CC8.1;

Organization Config rules are deployed but member accounts can modify or delete their local copies. A member admin can change rule parameters (weakening thresholds), disable rules (stopping evaluation), or delete rules (removing checks). The organizational baseline is overridable at the account level.

**Remediation:** Add an SCP that denies config:DeleteConfigRule, config:PutConfigRule, config:DeleteOrganizationConfigRule, and config:PutOrganizationConfigRule for organization-deployed rules in member accounts (with an exception for the delegated admin account). The SCP makes the organization rule set the authoritative baseline regardless of member account IAM posture.

---

### CTL.CONFIG.ORG.NOCONFORMANCE.001

**Organization Has No Organization Conformance Pack Deployed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: CA-2, CA-7, CM-6; iso_27001_2022: A.5.36, A.8.9; nist_800_53_r5: CA-2, CA-7, CM-6, AC-3; pci_dss_v4.0: 12.4; soc2: CC7.1, CC8.1;

AWS Organization spans multiple member accounts but no organization conformance pack is deployed. Per-account conformance packs require each member account to deploy independently, and they drift — some accounts have the pack, others don't, parameter overrides differ across accounts. An organization conformance pack deploys uniformly to all member accounts from the management or delegated-admin account, and the configuration is authoritative across the organization. Without one, the org-wide compliance baseline is whatever individual accounts happened to deploy.

**Remediation:** Deploy an organization conformance pack from the management account or delegated administrator: aws configservice put-organization-conformance-pack --organization-conformance-pack-name <name> --template-s3-uri <uri> --excluded-accounts (optional). The pack deploys uniformly to all member accounts in the organization. Pair with the delegated administrator (CTL.CONFIG.ORG.NODELEGATED.001) so org Config is administered outside the management account.

---

### CTL.CONFIG.ORG.NODELEGATED.001

**AWS Organization Has No Delegated Administrator for Config**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6, CM-5; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-3, AC-6, CM-5; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC8.1;

AWS Organization runs Config across member accounts but has not registered a delegated administrator account for config.amazonaws.com. Without delegation, organization-level Config administration — org rules, org conformance packs, aggregator authorization — must happen from the management account, which AWS best-practice guidance discourages exposing to day-to-day administrative workloads. The management account holds billing, root user, and the organization itself; concentrating Config admin there means the same identity boundary owns the audit-tool layer it should be evaluating independently.

**Remediation:** Register a dedicated security or audit account as the delegated administrator for Config: aws organizations register-delegated-administrator --account-id <security-acct> --service-principal config.amazonaws.com. Move org rule, org conformance pack, and aggregator administration to that account. The management account retains the ability to revoke delegation but shouldn't be the day-to-day admin point.

---

### CTL.CONFIG.ORG.NORULES.001

**No Organization Config Rules Deployed**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, CM-6; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-6; pci_dss_v4.0: 11.5; soc2: CC7.1, CC8.1;

AWS Organizations is in use but no organization-level Config rules are deployed. Each member account configures rules independently — or doesn't configure them at all. Without organization rules, compliance evaluation is inconsistent across the organization: some accounts evaluate encryption, others don't; some accounts evaluate IAM MFA, others don't.

**Remediation:** Deploy organization Config rules from the management or delegated admin account: aws configservice put-organization-config-rule --organization-config-rule-name <name> --organization-managed-rule-metadata RuleIdentifier=<id>. Start with a baseline set covering the most common security rules (S3 encryption, IAM MFA, CloudTrail enabled, security group rules) and expand as compliance requirements grow. Member- account admins cannot delete or modify organization rules locally.

---

### CTL.CONFIG.ORG.NOTALLACCOUNTS.001

**Config Not Enabled in All Member Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CA-7, CM-8; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-8; pci_dss_v4.0: 10.1, 11.5; soc2: CC7.1, CC8.1;

AWS Organizations is in use but Config is not enabled (no recorder running) in every member account. Some accounts have no configuration recording at all — resources in those accounts are completely invisible to Config. No configuration history, no compliance evaluation, no change tracking.

**Remediation:** Deploy Config to all member accounts via StackSets or Control Tower. Bake Config enablement into the account-creation process so new accounts have Config from day one. Use organization Config rules to apply a consistent baseline across all accounts.

---

### CTL.CONFIG.ORG.REMEDIATION.NOCENTRAL.001

**Organization Has No Centralized Remediation for Org-Wide Non-Compliance**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, IR-4, RA-5; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: CA-7, IR-4, RA-5, SI-4; pci_dss_v4.0: 11.5, 12.10; soc2: CC7.2, CC8.1;

Organization-level Config rules detect non- compliance in member accounts but remediation is configured (if at all) per account. There is no centralized remediation pipeline that fires when an org rule produces non-compliant findings across the organization. Each member account either remediates locally (drifts in approach), doesn't remediate (relies on humans to notice), or has remediation configured but inconsistently. The org rule's value is partly wasted — detection is uniform, response is fragmented.

**Remediation:** Either deploy organization remediation actions tied to the org rules (so remediation deploys to member accounts alongside the rule) or set up an aggregation-and-respond pipeline: aggregator surfaces non-compliance, an EventBridge rule fires on new non- compliant findings, and a centralized Lambda or SSM automation responds. Document the remediation flow so auditors can trace detection-to-response end-to-end.

---

### CTL.CONFIG.RECORDER.NOGLOBAL.001

**Config Recorder Does Not Include Global Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AC-2, CM-8; hipaa: 164.308(a)(4)(ii)(B); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AC-2, AC-3, CM-8, SA-10; pci_dss_v4.0: 7.2, 10.1; soc2: CC6.1, CC7.1, CC8.1;

AWS Config recorder has IncludeGlobalResourceTypes set to false. Global resources — IAM users, roles, policies, groups — are not recorded. IAM is the identity and access foundation for every AWS service; without recording it, Config has no visibility into IAM configuration changes.

**Remediation:** Enable global resource recording in exactly one region (typically us-east-1) — global resources should be recorded once per account, not per region: aws configservice put-configuration-recorder --configuration-recorder name=<name>,roleARN=<role>,recordingGroup={allSupported=true,includeGlobalResourceTypes=true} in us-east-1, and includeGlobalResourceTypes=false in all other regions.

---

### CTL.CONFIG.RECORDER.NOTALLREGIONS.001

**Config Recorder Not Running in All Active Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: AU-2, CA-7, CM-2; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-2, CA-7, CM-2, CM-8; pci_dss_v4.0: 10.2, 11.5; soc2: CC7.1, CC7.2;

AWS Config recorders are running in some regions but not all regions where the account has resources. Resources in unrecorded regions are completely invisible to Config — they don't appear in the configuration inventory, no rule evaluates them, no compliance status applies to them. An attacker who creates resources in a region without a recorder evades every Config-based detection. Most accounts should run a recorder in every region they use, regardless of how few resources are there; the cost of the recorder is small, the cost of an unrecorded blast-radius region is large.

**Remediation:** Either provision a Config recorder in every active region (aws configservice put-configuration-recorder per region — AWS publishes Terraform / CloudFormation templates to deploy recorders across regions), or restrict resource creation to a smaller region set via SCP and record those. For organizations, deploy via CloudFormation StackSets or AWS Control Tower's account baseline so the recorder is provisioned automatically in every region of every member account.

---

### CTL.CONFIG.RECORDER.NOTALLRESOURCES.001

**Config Recorder Does Not Record All Resource Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CM-2, CM-8; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CM-2, CM-3, CM-8, SA-10; pci_dss_v4.0: 10.1, 11.5; soc2: CC7.1, CC8.1;

AWS Config recorder is configured to record only specific resource types — not all supported types. Resource types not in scope are invisible to Config; rules evaluating them return no results (not non-compliant — no data). New AWS resource types added after recorder configuration are automatically excluded.

**Remediation:** Update the recorder to record all supported resource types: aws configservice put-configuration-recorder --configuration-recorder name=<name>,roleARN=<role>,recordingGroup={allSupported=true,includeGlobalResourceTypes=true}. Confirm via aws configservice describe-configuration-recorders that allSupported is true and review the next configuration history file to verify new resource types are captured.

---

### CTL.CONFIG.RECORDER.PERIODIC.001

**Config Recorder Uses Periodic Instead of Continuous Recording**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3, CM-8; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CM-3, CM-8, SI-4; pci_dss_v4.0: 10.1, 11.5; soc2: CC7.1, CC7.2;

AWS Config recorder is set to periodic mode instead of continuous. Periodic mode captures configuration only every 24 hours; changes between snapshots are not captured. A resource can be created, modified, and deleted within a 24-hour window without any Config record.

**Remediation:** Switch the recorder to continuous mode: aws configservice put-configuration-recorder --configuration-recorder name=<name>,roleARN=<role>,recordingMode={recordingFrequency=CONTINUOUS}. Continuous mode captures every configuration change as it occurs and is the default for most setups; periodic mode is intended for resource types with less-frequent changes or cost-sensitive accounts.

---

### CTL.CONFIG.RECORDER.ROLE.TRUST.BROAD.001

**Config Recorder Service Role Trusts Services Beyond config.amazonaws.com**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-3, AC-6, IA-2; iso_27001_2022: A.5.15, A.5.16; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC8.1;

AWS Config recorder service role trust policy allows services other than config.amazonaws.com to assume the role. The recorder role typically holds broad read access across resource types — IAM, EC2, S3, Lambda, RDS, every recorded type. With trust extended to additional services (or to specific account principals beyond Config), the role becomes a generic high-privilege handle reachable by other AWS-internal callers. The service role should be scoped narrowly to the single service that legitimately needs it: aws Config.

**Remediation:** Update the recorder role's trust policy to allow only the Config service: aws iam update-assume-role-policy --role-name <recorder-role> --policy-document with Principal: {"Service": "config.amazonaws.com"}. Audit who originally added the additional trust entries (CloudTrail) — extra entries are usually deliberate mistakes or short-term workarounds; verify the rationale or remove.

---

### CTL.CONFIG.REMEDIATION.001

**Critical Config Rules Must Have Automatic Remediation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-6; nist_800_53_r5: CM-6; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.CONFIG.REMEDIATION.GHOST.ROLE.001

**Config Remediation IAM Role Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CA-7, CM-3; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CA-7, CM-3, CM-4, SI-7; pci_dss_v4.0: 11.5; soc2: CC7.2, CC8.1;

AWS Config remediation action has an IAM role that has been deleted. The SSM document exists; the remediation triggers; SSM attempts to assume the role; AssumeRole fails. The remediation cannot execute.

**Remediation:** Recreate the IAM role with the SSM and target-service permissions the document requires (the document's documented permission set), or repoint the remediation at an existing role: aws configservice put-remediation-configurations with the new RoleARN. After fix, validate by triggering a non-compliance scenario and confirming the remediation completes.

---

### CTL.CONFIG.REMEDIATION.GHOST.SSM.001

**Config Remediation References Deleted SSM Document**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CA-7, CM-3; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CA-7, CM-3, CM-4, SI-7; pci_dss_v4.0: 11.5; soc2: CC7.2, CC8.1;

AWS Config remediation action references an SSM Automation document that has been deleted. When the rule detects non-compliance and triggers remediation, the SSM execution fails (document not found). The non-compliant resource is not fixed.

**Remediation:** Either redeploy the SSM Automation document with the same name (preserving the remediation configuration) or update the rule's remediation to point at a replacement document: aws configservice put-remediation-configurations with the new document name. Verify by triggering a non-compliance scenario and confirming auto-remediation completes.

---

### CTL.CONFIG.REMEDIATION.NONE.001

**AWS Config Must Have At Least One Remediation Action Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IR-4; scs_c02: 12.1; soc2: CC7.4;

AWS Config should have at least one automatic remediation action configured across its rules. Config without remediation is detect- only — it identifies non-compliant resources but takes no corrective action. For incident response automation, Config remediation actions (via SSM Automation documents) provide the mechanism to automatically correct security drift without manual intervention.

**Remediation:** Configure remediation actions on critical Config rules using SSM Automation documents. Start with high-severity rules like s3-bucket-public-read-prohibited, encrypted-volumes, and iam-password-policy.

---

### CTL.CONFIG.REMEDIATION.RETRIES.EXHAUSTED.001

**Config Remediation Retries Exhausted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, IR-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CA-7, CM-3, IR-4, SI-4; pci_dss_v4.0: 11.5, 12.10; soc2: CC7.2, CC8.1;

AWS Config remediation has exhausted its retry attempts. The remediation tried to fix non- compliant resources, failed each time, and has stopped retrying. Resources remain non- compliant. The configuration is in place; the fix gave up.

**Remediation:** Inspect the failure reason. Permission denied: the remediation role lacks a needed action — update the policy. Resource protected: a Deny statement (SCP, resource policy) overrides the remediation — coordinate with the policy owner. SSM document logic error: the document hits an unhandled edge case — patch the document. After the underlying fix, manually trigger remediation: aws configservice start-remediation-execution --config-rule-name <rule> --resource-keys <list>.

---

### CTL.CONFIG.RULE.DISABLED.001

**Config Rule Is Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CA-7, CM-6; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-6, SI-4; pci_dss_v4.0: 11.5; soc2: CC7.1, CC7.2, CC8.1;

AWS Config rule exists but is in disabled state. The rule has a name, scope, parameters, and evaluation logic — but it doesn't evaluate. The rule appears to exist; it doesn't function. Same false-protection shape as DLM disabled, alarm ActionsEnabled false, and WAF without rules.

**Remediation:** Re-enable the rule via the Config console or aws configservice put-config-rule with the State field set appropriately. If the rule was disabled to suppress a known issue, fix the underlying configuration before re- enabling. Document the reason for any intentional, persistent disable in change management so it doesn't appear as a forgotten artifact at the next audit.

---

### CTL.CONFIG.RULE.GHOST.LAMBDA.001

**Config Custom Rule References Deleted Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CA-7, CM-3; hipaa: 164.312(b); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-3, SI-4; pci_dss_v4.0: 11.5; soc2: CC7.1, CC8.1;

AWS Config custom rule references a Lambda function that has been deleted. Custom rules delegate evaluation to a Lambda function — the function receives the configuration item and returns COMPLIANT or NON_COMPLIANT. When the Lambda is deleted, evaluation fails and the resource's compliance status becomes unknown.

**Remediation:** Either redeploy the Lambda function with the same ARN (preserving rule configuration) or update the rule to point at a replacement Lambda: aws configservice put-config-rule with Source.SourceIdentifier set to the new function ARN. If the Lambda's logic is no longer needed, delete the rule rather than leaving an orphan.

---

### CTL.CONFIG.RULE.LAMBDA.ERROR.001

**Config Custom Rule Lambda Errors on Every Evaluation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CA-7, SI-4; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, SI-4; pci_dss_v4.0: 11.5; soc2: CC7.1, CC8.1;

AWS Config custom rule's Lambda function exists but errors on every evaluation — throws exceptions, times out, or returns invalid responses. The rule triggers, the Lambda runs, the Lambda fails, and every evaluation returns an error. Compliance status is unknown for every resource the rule evaluates. Distinct from GHOST.LAMBDA where the Lambda is deleted — here the Lambda exists but cannot complete.

**Remediation:** Inspect the Lambda's CloudWatch logs for the failure pattern (uncaught exception, timeout, bad response shape). Common causes: stale SDK version, missing IAM permission for the Lambda execution role, unhandled configuration item shape after AWS added a new field. Fix and redeploy. If the Lambda's logic is no longer maintainable, replace with an AWS-managed rule covering the same requirement.

---

### CTL.CONFIG.RULE.NONCOMPLIANT.NOREMEDIATION.001

**Config Rule Has Non-Compliant Resources But No Remediation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, CM-3; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CA-7, CM-3, CM-4, SI-7; pci_dss_v4.0: 11.5, 12.10; soc2: CC7.2, CC7.3, CC8.1;

AWS Config rule has detected non-compliant resources but no remediation action is configured — neither automatic nor manual. Detection without remediation is half the value: the organization knows about the non-compliance and accepts the risk indefinitely or fails to act on the findings.

**Remediation:** Either configure a remediation action for the rule (Config → Rule → Remediation action with an SSM Automation document) or document an explicit accept-risk decision in change management with a review date. Persistent non-compliance without one of those two outcomes is compliance theater. For high-severity non-compliance (public buckets, root account use, MFA-less users), the fix path should be auto-remediation.

---

### CTL.CONFIG.RULE.NOTALLREGIONS.001

**Config Rules Not Deployed in All Active Regions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 3.5; fedramp_moderate: CA-7, CM-6; iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: CA-7, CM-2, CM-6; pci_dss_v4.0: 11.5; soc2: CC7.1, CC8.1;

AWS Config rules are deployed in some regions but not all regions where the recorder is running. Resources in regions without rules are recorded but not evaluated — Config captures their configuration but no rule judges whether they're compliant.

**Remediation:** Deploy the same Config rule set across all regions where the recorder runs. Use StackSets, CloudFormation, or Terraform to keep rules in sync; per-region manual deployment drifts. For organization-wide deployment, organization Config rules deploy uniformly across all member accounts and regions in scope.

---

### CTL.CONFIG.RULE.STATUS.001

**Config Rules Must Not Be in ERROR State**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC7.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.CONFIG.RULES.001

**AWS Config Must Have Active Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; hipaa: 164.312(c)(1); nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC6.3;

AWS Config must have active Config Rules to evaluate resource compliance. Recording without rules provides change history but no automated drift detection.

**Remediation:** Deploy Config Rules for your compliance requirements. Start with AWS managed rules for common checks (encrypted-volumes, restricted-common-ports, etc).

---

### CTL.CONFIG.SERVICEROLE.001

**AWS Config Must Use the Service-Linked Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

AWS Config recorders must use the AWS-managed service-linked role AWSServiceRoleForConfig rather than a custom IAM role. Custom roles may have excessive or insufficient permissions and are not automatically updated when Config adds support for new resources.

**Remediation:** Switch to the AWSServiceRoleForConfig service-linked role.

---

